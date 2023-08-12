#include "netguard.h"

int get_icmp_timeout(const struct icmp_session *u, int sessions, int maxsessions) {
    int timeout = ICMP_TIMEOUT;

    int scale = 100 - sessions * 100 / maxsessions;
    timeout = timeout * scale / 100;

    return timeout;
}

// Function to check the ICMP session for activity and determine if it should be closed
int check_icmp_session(const struct arguments *args, struct ng_session *s,
                       int sessions, int maxsessions) {
    // Get the current time
    time_t now = time(NULL);
    // Calculate the timeout for the ICMP session based on current sessions and max sessions
    int timeout = get_icmp_timeout(&s->icmp, sessions, maxsessions);
    // Check if the ICMP session has been inactive longer than its timeout or if it should be stopped
    if (s->icmp.stop || s->icmp.time + timeout < now) {
        // Convert the source and destination IP addresses from binary to text format for logging
        char source[INET6_ADDRSTRLEN + 1];
        char dest[INET6_ADDRSTRLEN + 1];
        inet_ntop(AF_INET, &s->icmp.saddr.ip4, source, sizeof(source));
        inet_ntop(AF_INET, &s->icmp.daddr.ip4, dest, sizeof(dest));
        // Log the inactivity details of the ICMP session
        log_android(ANDROID_LOG_WARN, "ICMP idle %d/%d sec stop %d from %s to %s",
                    now - s->icmp.time, timeout, s->icmp.stop, dest, source);
        // Close the socket associated with the ICMP session
        if (close(s->socket))
            log_android(ANDROID_LOG_ERROR, "ICMP close %d error %d: %s",
                        s->socket, errno, strerror(errno));
        // Set the session's socket descriptor to an invalid value
        s->socket = -1;
        // Return 1 indicating that the session should be removed
        return 1;
    }
    // Return 0 indicating that the session is still active and should not be removed
    return 0;
}

void check_icmp_socket(const struct arguments *args, const struct epoll_event *ev) {
    // Convert the data pointer from the epoll event to an ICMP session structure
    struct ng_session *s = (struct ng_session *) ev->data.ptr;
    // Check for errors on the socket
    if (ev->events & EPOLLERR) {
        // Update the last activity timestamp of the ICMP session
        s->icmp.time = time(NULL);

        int serr = 0;
        socklen_t optlen = sizeof(int);
        // Get and check the error status on the socket
        int err = getsockopt(s->socket, SOL_SOCKET, SO_ERROR, &serr, &optlen);
        if (err < 0)
            // Log if there's an error fetching the socket status
            log_android(ANDROID_LOG_ERROR, "ICMP getsockopt error %d: %s",
                        errno, strerror(errno));
        else if (serr)
            // Log the socket error status
            log_android(ANDROID_LOG_ERROR, "ICMP SO_ERROR %d: %s",
                        serr, strerror(serr));
        // Flag the ICMP session to be stopped due to the error
        s->icmp.stop = 1;
    } else {
        // Check if there's data available to read on the socket
        if (ev->events & EPOLLIN) {
            // Update the last activity timestamp of the ICMP session
            s->icmp.time = time(NULL);
            // Allocate a buffer to read the data
            uint16_t blen = (uint16_t) ICMP4_MAXMSG;
            uint8_t *buffer = malloc(blen);
            // Receive the data from the socket
            ssize_t bytes = recv(s->socket, buffer, blen, 0);
            if (bytes < 0) {
                // Log the error if reading from the socket fails
                log_android(ANDROID_LOG_WARN, "ICMP recv error %d: %s",
                            errno, strerror(errno));
                // Check if the error isn't temporary and flag the session to be stopped
                if (errno != EINTR && errno != EAGAIN)
                    s->icmp.stop = 1;
            } else if (bytes == 0) {
                // Log if the socket has reached end-of-file (remote side closed connection)
                log_android(ANDROID_LOG_WARN, "ICMP recv eof");
                s->icmp.stop = 1;
            } else {
                // Convert the destination IP address from binary to text format for logging
                char dest[INET6_ADDRSTRLEN + 1];
                if (s->icmp.version == 4)
                    inet_ntop(AF_INET, &s->icmp.daddr.ip4, dest, sizeof(dest));
                else
                    inet_ntop(AF_INET6, &s->icmp.daddr.ip6, dest, sizeof(dest));

                // cur->id should be equal to icmp->icmp_id
                // but for some unexplained reason this is not the case
                // some bits seems to be set extra
                // Extract ICMP details from the received buffer
                struct icmp *icmp = (struct icmp *) buffer;
                // Log the details of the received ICMP packet
                log_android(
                        s->icmp.id == icmp->icmp_id ? ANDROID_LOG_INFO : ANDROID_LOG_WARN,
                        "ICMP recv bytes %d from %s for tun type %d code %d id %x/%x seq %d",
                        bytes, dest,
                        icmp->icmp_type, icmp->icmp_code,
                        s->icmp.id, icmp->icmp_id, icmp->icmp_seq);

                // Restore the original ICMP ID in the packet
                icmp->icmp_id = s->icmp.id;
                uint16_t csum = 0;
                icmp->icmp_cksum = 0;
                // Recalculate the checksum for the ICMP packet
                icmp->icmp_cksum = ~calc_checksum(csum, buffer, (size_t) bytes);

                // Forward the ICMP packet to the tun interface
                if (write_icmp(args, &s->icmp, buffer, (size_t) bytes) < 0)
                    s->icmp.stop = 1;
            }
            // Free the allocated buffer
            free(buffer);
        }
    }
}

// Function to handle ICMP packets
jboolean handle_icmp(const struct arguments *args,
                     const uint8_t *pkt, size_t length,
                     const uint8_t *payload,
                     int uid,
                     const int epoll_fd) {

    // Determine IP version from the packet header (IPv4 or IPv6)
    const uint8_t version = (*pkt) >> 4;

    // Cast packet data to IPv4 and IPv6 header structures
    const struct iphdr *ip4 = (struct iphdr *) pkt;
    const struct ip6_hdr *ip6 = (struct ip6_hdr *) pkt;
    // Cast payload to ICMP structure
    struct icmp *icmp = (struct icmp *) payload;
    // Calculate the length of the ICMP packet
    size_t icmplen = length - (payload - pkt);

    // Buffer to store the source and destination IP addresses as strings
    char source[INET6_ADDRSTRLEN + 1];
    char dest[INET6_ADDRSTRLEN + 1];

    // Convert IP addresses to human-readable strings based on the IP version
    inet_ntop(AF_INET, &ip4->saddr, source, sizeof(source));
    inet_ntop(AF_INET, &ip4->daddr, dest, sizeof(dest));


    // Ignore ICMP packets other than echo requests (ping)
    if (icmp->icmp_type != ICMP_ECHO) {
        log_android(ANDROID_LOG_WARN, "ICMP type %d code %d from %s to %s not supported",
                    icmp->icmp_type, icmp->icmp_code, source, dest);
        return 0;
    }

    // Search for an existing session for this ICMP packet
    struct ng_session *cur = args->ctx->ng_session;
    while (cur != NULL &&
           !((cur->protocol == IPPROTO_ICMP || cur->protocol == IPPROTO_ICMPV6) &&
             !cur->icmp.stop && cur->icmp.version == version &&
             (version == 4 ? cur->icmp.saddr.ip4 == ip4->saddr &&
                             cur->icmp.daddr.ip4 == ip4->daddr
                           : memcmp(&cur->icmp.saddr.ip6, &ip6->ip6_src, 16) == 0 &&
                             memcmp(&cur->icmp.daddr.ip6, &ip6->ip6_dst, 16) == 0)))
        cur = cur->next;

    // If no session found, create a new one
    if (cur == NULL) {
        log_android(ANDROID_LOG_INFO, "ICMP new session from %s to %s", source, dest);
        // Allocate memory for the new session and initialize its values
        struct ng_session *s = malloc(sizeof(struct ng_session));
        s->protocol = (uint8_t) (version == 4 ? IPPROTO_ICMP : IPPROTO_ICMPV6);

        s->icmp.time = time(NULL);
        s->icmp.uid = uid;
        s->icmp.version = version;

        // Store IP addresses in the session
        s->icmp.saddr.ip4 = (__be32) ip4->saddr;
        s->icmp.daddr.ip4 = (__be32) ip4->daddr;

        // Store the original ICMP ID in the session
        s->icmp.id = icmp->icmp_id; // store original ID

        s->icmp.stop = 0;
        s->next = NULL;

        // Open a socket to handle ICMP traffic for this session
        s->socket = open_icmp_socket(args, &s->icmp);
        if (s->socket < 0) {
            free(s);
            return 0;
        }

        log_android(ANDROID_LOG_DEBUG, "ICMP socket %d id %x", s->socket, s->icmp.id);

        // Monitor socket events using epoll
        memset(&s->ev, 0, sizeof(struct epoll_event));
        s->ev.events = EPOLLIN | EPOLLERR;
        s->ev.data.ptr = s;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, s->socket, &s->ev))
            log_android(ANDROID_LOG_ERROR, "epoll add icmp error %d: %s", errno, strerror(errno));

        // Add the session to the list of sessions
        s->next = args->ctx->ng_session;
        args->ctx->ng_session = s;
        cur = s;
    }

    // Modify the ICMP ID for echo reply
    // http://lwn.net/Articles/443051/
    icmp->icmp_id = ~icmp->icmp_id;
    // Calculate the checksum for IPv6 ICMP packets (this part is marked as untested)
    uint16_t csum = 0;
    // Recalculate the ICMP checksum
    icmp->icmp_cksum = 0;
    icmp->icmp_cksum = ~calc_checksum(csum, (uint8_t *) icmp, icmplen);

    log_android(ANDROID_LOG_INFO,
                "ICMP forward from tun %s to %s type %d code %d id %x seq %d data %d",
                source, dest,
                icmp->icmp_type, icmp->icmp_code, icmp->icmp_id, icmp->icmp_seq, icmplen);
    // Update the last activity timestamp for this session
    cur->icmp.time = time(NULL);
    // Prepare socket address structures to send the modified ICMP message
    struct sockaddr_in server4;
    struct sockaddr_in6 server6;
    server4.sin_family = AF_INET;
    server4.sin_addr.s_addr = (__be32) ip4->daddr;
    server4.sin_port = 0;


    // Send the modified ICMP message
    if (sendto(cur->socket, icmp, (socklen_t) icmplen, MSG_NOSIGNAL,
               (version == 4 ? (const struct sockaddr *) &server4
                             : (const struct sockaddr *) &server6),
               (socklen_t) (version == 4 ? sizeof(server4) : sizeof(server6))) != icmplen) {
        log_android(ANDROID_LOG_ERROR, "ICMP sendto error %d: %s", errno, strerror(errno));
        if (errno != EINTR && errno != EAGAIN) {
            cur->icmp.stop = 1;
            return 0;
        }
    }

    return 1;
}

int open_icmp_socket(const struct arguments *args, const struct icmp_session *cur) {
    int sock;

    // Get UDP socket
    sock = socket(cur->version == 4 ? PF_INET : PF_INET6, SOCK_DGRAM, IPPROTO_ICMP);
    if (sock < 0) {
        log_android(ANDROID_LOG_ERROR, "ICMP socket error %d: %s", errno, strerror(errno));
        return -1;
    }

    // Protect socket
    if (protect_socket(args, sock) < 0)
        return -1;

    return sock;
}

ssize_t write_icmp(const struct arguments *args, const struct icmp_session *cur,
                   uint8_t *data, size_t datalen) {
    size_t len;
    u_int8_t *buffer;
    struct icmp *icmp = (struct icmp *) data;
    char source[INET6_ADDRSTRLEN + 1];
    char dest[INET6_ADDRSTRLEN + 1];

    // Build packet
    if (cur->version == 4) {
        len = sizeof(struct iphdr) + datalen;
        buffer = malloc(len);
        struct iphdr *ip4 = (struct iphdr *) buffer;
        if (datalen)
            memcpy(buffer + sizeof(struct iphdr), data, datalen);

        // Build IP4 header
        memset(ip4, 0, sizeof(struct iphdr));
        ip4->version = 4;
        ip4->ihl = sizeof(struct iphdr) >> 2;
        ip4->tot_len = htons(len);
        ip4->ttl = IPDEFTTL;
        ip4->protocol = IPPROTO_ICMP;
        ip4->saddr = cur->daddr.ip4;
        ip4->daddr = cur->saddr.ip4;

        // Calculate IP4 checksum
        ip4->check = ~calc_checksum(0, (uint8_t *) ip4, sizeof(struct iphdr));
    } else {

    }

    inet_ntop(cur->version == 4 ? AF_INET : AF_INET6,
              cur->version == 4 ? (const void *) &cur->saddr.ip4 : (const void *) &cur->saddr.ip6,
              source, sizeof(source));
    inet_ntop(cur->version == 4 ? AF_INET : AF_INET6,
              cur->version == 4 ? (const void *) &cur->daddr.ip4 : (const void *) &cur->daddr.ip6,
              dest, sizeof(dest));

    // Send raw ICMP message
    log_android(ANDROID_LOG_WARN,
                "ICMP sending to tun %d from %s to %s data %u type %d code %d id %x seq %d",
                args->tun, dest, source, datalen,
                icmp->icmp_type, icmp->icmp_code, icmp->icmp_id, icmp->icmp_seq);

    ssize_t res = write(args->tun, buffer, len);

    free(buffer);

    if (res != len) {
        log_android(ANDROID_LOG_ERROR, "write %d/%d", res, len);
        return -1;
    }

    return res;
}
