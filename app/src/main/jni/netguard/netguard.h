// Including necessary header files for various functionalities
#include <jni.h> // Provides JNI (Java Native Interface) related functionalities
#include <android/log.h> // Android logging
#include <stdio.h> // For standard input-output functions
#include <stdlib.h> // For standard library functions like memory allocations
#include <ctype.h> // For character handling functions
#include <time.h> // For time-related functions and structures
#include <unistd.h> // For POSIX operating system API
#include <setjmp.h> // For jump functions
#include <errno.h> // For error number definitions
#include <fcntl.h> // For file control options
#include <dirent.h> // For directory entries
#include <poll.h> // For poll system calls
#include <sys/types.h> // For system data types
#include <sys/ioctl.h> // For I/O control device specific operations
#include <sys/socket.h> // For socket programming
#include <sys/epoll.h> // For epoll system calls
#include <dlfcn.h> // For dynamic linking
#include <sys/stat.h> // For file status
#include <sys/resource.h> // For resource operations
// Various network related header files
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/in6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <sys/system_properties.h>  // For system properties


#define TAG "NetGuard.JNI" // Logging tag


// Various constants for network handling
#define EPOLL_TIMEOUT 3600 // seconds
#define EPOLL_EVENTS 20
#define EPOLL_MIN_CHECK 100 // milliseconds
// Maximum message sizes for different protocols
#define ICMP4_MAXMSG (IP_MAXPACKET - 20 - 8) // bytes (socket)
#define ICMP6_MAXMSG (IPV6_MAXPACKET - 40 - 8) // bytes (socket)
#define UDP4_MAXMSG (IP_MAXPACKET - 20 - 8) // bytes (socket)
#define UDP6_MAXMSG (IPV6_MAXPACKET - 40 - 8) // bytes (socket)

// Various timeout values
#define ICMP_TIMEOUT 15 // seconds
#define UDP_TIMEOUT_53 15 // seconds
#define UDP_TIMEOUT_ANY 300 // seconds
#define UDP_KEEP_TIMEOUT 60 // seconds
#define TCP_INIT_TIMEOUT 30 // seconds ~net.inet.tcp.keepinit
#define TCP_IDLE_TIMEOUT 3600 // seconds ~net.inet.tcp.keepidle
#define TCP_CLOSE_TIMEOUT 30 // seconds
#define TCP_KEEP_TIMEOUT 300 // seconds
// https://en.wikipedia.org/wiki/Maximum_segment_lifetime
// Session related constants
#define SESSION_MAX 512 // number
#define SESSION_LIMIT 30 // percent
#define UID_MAX_AGE 30000 // milliseconds
#define SOCKS5_NONE 1
#define SOCKS5_HELLO 2
#define SOCKS5_AUTH 3
#define SOCKS5_CONNECT 4
#define SOCKS5_CONNECTED 5

// Structure definitions and other constants follow...
struct context {
    int pipefds[2];
    int stopping;
    int tun;
    struct ng_session *ng_session;
};

struct arguments {
    JNIEnv *env;
    jobject instance;
    int sdk;
    int tun;
    jboolean fwd53;
    jint rcode;
    struct context *ctx;
};

struct allowed {
    char raddr[INET6_ADDRSTRLEN + 1]; // The IP address of the remote endpoint.
    uint16_t rport; // The port number of the remote endpoint.
};

struct segment {
    uint32_t seq;
    uint16_t len;
    uint16_t sent;
    int psh;
    uint8_t *data;
    struct segment *next;
};

struct icmp_session {
    time_t time;
    jint uid;
    int version;
    union {
        __be32 ip4; // network notation
        struct in6_addr ip6;
    } saddr;
    union {
        __be32 ip4; // network notation
        struct in6_addr ip6;
    } daddr;
    uint16_t id;
    uint8_t stop;
};

#define UDP_ACTIVE 0
#define UDP_FINISHING 1
#define UDP_CLOSED 2
#define UDP_BLOCKED 3

struct udp_session {
    time_t time;
    jint uid;
    int version;
    uint16_t mss;

    uint64_t sent;
    uint64_t received;

    union {
        __be32 ip4; // network notation
        struct in6_addr ip6;
    } saddr;
    __be16 source; // network notation

    union {
        __be32 ip4; // network notation
        struct in6_addr ip6;
    } daddr;
    __be16 dest; // network notation

    uint8_t state;
};

struct tcp_session {
    jint uid;
    time_t time;
    int version;
    uint16_t mss;
    uint8_t recv_scale;
    uint8_t send_scale;
    uint32_t recv_window; // host notation, scaled
    uint32_t send_window; // host notation, scaled

    uint32_t remote_seq; // confirmed bytes received, host notation
    uint32_t local_seq; // confirmed bytes sent, host notation
    uint32_t remote_start;
    uint32_t local_start;

    uint32_t acked; // host notation
    long long last_keep_alive;

    uint64_t sent;
    uint64_t received;

    union {
        __be32 ip4; // network notation
        struct in6_addr ip6;
    } saddr;
    __be16 source; // network notation

    union {
        __be32 ip4; // network notation
        struct in6_addr ip6;
    } daddr;
    __be16 dest; // network notation

    uint8_t state;
    uint8_t socks5;
    struct segment *forward;
};

struct ng_session {
    uint8_t protocol;
    union {
        struct icmp_session icmp;
        struct udp_session udp;
        struct tcp_session tcp;
    };
    jint socket;
    struct epoll_event ev;
    struct ng_session *next;
};

struct uid_cache_entry {
    uint8_t version;
    uint8_t protocol;
    uint8_t saddr[16];
    uint16_t sport;
    uint8_t daddr[16];
    uint16_t dport;
    jint uid;
    long time;
};



// DNS
#define DNS_QCLASS_IN 1
#define DNS_QTYPE_A 1 // IPv4
#define DNS_QTYPE_AAAA 28 // IPv6

#define DNS_QNAME_MAX 255
#define DNS_TTL (10 * 60) // seconds

struct dns_header {
    uint16_t id; // identification number
# if __BYTE_ORDER == __LITTLE_ENDIAN
    uint16_t rd: 1; // recursion desired
    uint16_t tc: 1; // truncated message
    uint16_t aa: 1; // authoritive answer
    uint16_t opcode: 4; // purpose of message
    uint16_t qr: 1; // query/response flag
    uint16_t rcode: 4; // response code
    uint16_t cd: 1; // checking disabled
    uint16_t ad: 1; // authenticated data
    uint16_t z: 1; // its z! reserved
    uint16_t ra: 1; // recursion available
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint16_t qr :1; // query/response flag
    uint16_t opcode :4; // purpose of message
    uint16_t aa :1; // authoritive answer
    uint16_t tc :1; // truncated message
    uint16_t rd :1; // recursion desired
    uint16_t ra :1; // recursion available
    uint16_t z :1; // its z! reserved
    uint16_t ad :1; // authenticated data
    uint16_t cd :1; // checking disabled
    uint16_t rcode :4; // response code
# else
# error "Adjust your <bits/endian.h> defines"
#endif
    uint16_t q_count; // number of question entries
    uint16_t ans_count; // number of answer entries
    uint16_t auth_count; // number of authority entries
    uint16_t add_count; // number of resource entries
} __packed;

typedef struct dns_rr {
    __be16 qname_ptr;
    __be16 qtype;
    __be16 qclass;
    __be32 ttl;
    __be16 rdlength;
} __packed dns_rr;

// DHCP

#define DHCP_OPTION_MAGIC_NUMBER (0x63825363)

typedef struct dhcp_packet {
    uint8_t opcode;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint32_t option_format;
} __packed dhcp_packet;

// Prototypes
void *handle_events(void *a);

void report_exit(const struct arguments *args, const char *fmt, ...);

void report_error(const struct arguments *args, jint error, const char *fmt, ...);

void check_allowed(const struct arguments *args);

void clear(struct context *ctx);

int check_icmp_session(const struct arguments *args,
                       struct ng_session *s,
                       int sessions, int maxsessions);

int check_udp_session(const struct arguments *args,
                      struct ng_session *s,
                      int sessions, int maxsessions);

int check_tcp_session(const struct arguments *args,
                      struct ng_session *s,
                      int sessions, int maxsessions);

int monitor_tcp_session(const struct arguments *args, struct ng_session *s, int epoll_fd);

int get_icmp_timeout(const struct icmp_session *u, int sessions, int maxsessions);

int get_udp_timeout(const struct udp_session *u, int sessions, int maxsessions);

int get_tcp_timeout(const struct tcp_session *t, int sessions, int maxsessions);

uint16_t get_mtu();

uint16_t get_default_mss(int version);

int check_tun(const struct arguments *args,
              const struct epoll_event *ev,
              const int epoll_fd,
              int sessions, int maxsessions);

void check_icmp_socket(const struct arguments *args, const struct epoll_event *ev);

void check_udp_socket(const struct arguments *args, const struct epoll_event *ev);

int32_t get_qname(const uint8_t *data, const size_t datalen, uint16_t off, char *qname);

void parse_dns_response(const struct arguments *args, const struct udp_session *u,
                        const uint8_t *data, size_t *datalen);

uint32_t get_send_window(const struct tcp_session *cur);

int get_receive_buffer(const struct ng_session *cur);

uint32_t get_receive_window(const struct ng_session *cur);

void check_tcp_socket(const struct arguments *args,
                      const struct epoll_event *ev,
                      const int epoll_fd);

void handle_ip(const struct arguments *args,
               const uint8_t *buffer, size_t length,
               const int epoll_fd,
               int sessions, int maxsessions);

jboolean handle_icmp(const struct arguments *args,
                     const uint8_t *pkt, size_t length,
                     const uint8_t *payload,
                     int uid,
                     const int epoll_fd);

int has_udp_session(const struct arguments *args, const uint8_t *pkt, const uint8_t *payload);

void block_udp(const struct arguments *args,
               const uint8_t *pkt, size_t length,
               const uint8_t *payload,
               int uid);

jboolean handle_udp(const struct arguments *args,
                    const uint8_t *pkt, size_t length,
                    const uint8_t *payload,
                    int uid, struct allowed *redirect,
                    const int epoll_fd);

int get_dns_query(const struct arguments *args, const struct udp_session *u,
                  const uint8_t *data, const size_t datalen,
                  uint16_t *qtype, uint16_t *qclass, char *qname);

int check_domain(const struct arguments *args, const struct udp_session *u,
                 const uint8_t *data, const size_t datalen,
                 uint16_t qclass, uint16_t qtype, const char *name);

int check_dhcp(const struct arguments *args, const struct udp_session *u,
               const uint8_t *data, const size_t datalen);

void clear_tcp_data(struct tcp_session *cur);

jboolean handle_tcp(const struct arguments *args,
                    const uint8_t *pkt, size_t length,
                    const uint8_t *payload,
                    int uid, int allowed, struct allowed *redirect,
                    const int epoll_fd);

void queue_tcp(const struct arguments *args,
               const struct tcphdr *tcphdr,
               const char *session, struct tcp_session *cur,
               const uint8_t *data, uint16_t datalen);

int open_icmp_socket(const struct arguments *args, const struct icmp_session *cur);

int open_udp_socket(const struct arguments *args,
                    const struct udp_session *cur, const struct allowed *redirect);

int open_tcp_socket(const struct arguments *args,
                    const struct tcp_session *cur, const struct allowed *redirect);

int32_t get_local_port(const int sock);

int write_syn_ack(const struct arguments *args, struct tcp_session *cur);

int write_ack(const struct arguments *args, struct tcp_session *cur);

int write_data(const struct arguments *args, struct tcp_session *cur,
               const uint8_t *buffer, size_t length);

int write_fin_ack(const struct arguments *args, struct tcp_session *cur);

void write_rst(const struct arguments *args, struct tcp_session *cur);


ssize_t write_icmp(const struct arguments *args, const struct icmp_session *cur,
                   uint8_t *data, size_t datalen);

ssize_t write_udp(const struct arguments *args, const struct udp_session *cur,
                  uint8_t *data, size_t datalen);

ssize_t write_tcp(const struct arguments *args, const struct tcp_session *cur,
                  const uint8_t *data, size_t datalen,
                  int syn, int ack, int fin, int rst);

uint8_t char2nible(const char c);

void hex2bytes(const char *hex, uint8_t *buffer);

jint get_uid(const int version, const int protocol,
             const void *saddr, const uint16_t sport,
             const void *daddr, const uint16_t dport);

jint get_uid_sub(const int version, const int protocol,
                 const void *saddr, const uint16_t sport,
                 const void *daddr, const uint16_t dport,
                 const char *source, const char *dest,
                 long now);

int protect_socket(const struct arguments *args, int socket);

uint16_t calc_checksum(uint16_t start, const uint8_t *buffer, size_t length);

jobject jniGlobalRef(JNIEnv *env, jobject cls);

jclass jniFindClass(JNIEnv *env, const char *name);

jmethodID jniGetMethodID(JNIEnv *env, jclass cls, const char *name, const char *signature);

jfieldID jniGetFieldID(JNIEnv *env, jclass cls, const char *name, const char *type);

jobject jniNewObject(JNIEnv *env, jclass cls, jmethodID constructor, const char *name);

int jniCheckException(JNIEnv *env);

int sdk_int(JNIEnv *env);

void log_android(int prio, const char *fmt, ...);

void log_packet(const struct arguments *args, jobject jpacket);

void dns_resolved(const struct arguments *args,
                  const char *qname, const char *aname, const char *resource, int ttl);

jboolean is_domain_blocked(const struct arguments *args, const char *name);

struct allowed *is_address_allowed(const struct arguments *args, jobject objPacket);

jobject create_packet(const struct arguments *args,
                      jint version,
                      jint protocol,
                      const char *flags,
                      const char *source,
                      jint sport,
                      const char *dest,
                      jint dport,
                      const char *data,
                      jint uid,
                      jboolean allowed);

void account_usage(const struct arguments *args, jint version, jint protocol,
                   const char *daddr, jint dport, jint uid, jlong sent, jlong received);

int compare_u32(uint32_t seq1, uint32_t seq2);

const char *strstate(const int state);

char *hex(const u_int8_t *data, const size_t len);

int is_readable(int fd);

long long get_ms();
