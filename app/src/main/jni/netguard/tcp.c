#include "netguard.h"

extern char socks5_addr[INET6_ADDRSTRLEN + 1];
extern int socks5_port;
extern char socks5_username[127 + 1];
extern char socks5_password[127 + 1];

// Function to clear all TCP data segments for the given session
void clear_tcp_data(struct tcp_session *cur) {
    // Start at the first segment in the forward chain
    struct segment *s = cur->forward;
    while (s != NULL) {
        // Temporary pointer to the current segment
        struct segment *p = s;
        // Move to the next segment
        s = s->next;
        // Free the data of the current segment
        free(p->data);
        // Free the current segment itself
        free(p);
    }
}

// Function to get the timeout value for a given TCP session
int get_tcp_timeout(const struct tcp_session *t, int sessions, int maxsessions) {
    int timeout;
    // Set initial timeout based on session state
    if (t->state == TCP_LISTEN || t->state == TCP_SYN_RECV)
        timeout = TCP_INIT_TIMEOUT;
    else if (t->state == TCP_ESTABLISHED)
        timeout = TCP_IDLE_TIMEOUT;
    else
        timeout = TCP_CLOSE_TIMEOUT;

    // Adjust timeout based on the ratio of current sessions to max sessions
    int scale = 100 - sessions * 100 / maxsessions;
    timeout = timeout * scale / 100;

    return timeout;
}

// Function to check the validity and state of a given TCP session
int check_tcp_session(const struct arguments *args, struct ng_session *s,
                      int sessions, int maxsessions) {
    // Get current time
    time_t now = time(NULL);
    // Buffers for storing IP addresses in string format
    char source[INET6_ADDRSTRLEN + 1];
    char dest[INET6_ADDRSTRLEN + 1];
    // Convert IP addresses from binary to string
    inet_ntop(AF_INET, &s->tcp.saddr.ip4, source, sizeof(source));
    inet_ntop(AF_INET, &s->tcp.daddr.ip4, dest, sizeof(dest));

    // Construct a description of the session for logging
    char session[250];
    sprintf(session, "TCP socket from %s/%u to %s/%u %s socket %d",
            source, ntohs(s->tcp.source), dest, ntohs(s->tcp.dest),
            strstate(s->tcp.state), s->socket);
    // Calculate session timeout using the helper function
    int timeout = get_tcp_timeout(&s->tcp, sessions, maxsessions);

    // Check if the session has exceeded its timeout
    if (s->tcp.state != TCP_CLOSING && s->tcp.state != TCP_CLOSE &&
        s->tcp.time + timeout < now) {
        log_android(ANDROID_LOG_WARN, "%s idle %d/%d sec ", session, now - s->tcp.time,
                    timeout);
        if (s->tcp.state == TCP_LISTEN)
            s->tcp.state = TCP_CLOSING;
        else
            write_rst(args, &s->tcp);
    }

    // Handle closing sessions
    if (s->tcp.state == TCP_CLOSING) {
        // If socket is still open, close it
        if (s->socket >= 0) {
            if (close(s->socket))
                log_android(ANDROID_LOG_ERROR, "%s close error %d: %s",
                            session, errno, strerror(errno));
            else
                log_android(ANDROID_LOG_WARN, "%s close", session);
            s->socket = -1;
        }
        // Update session's timestamp and set its state to CLOSE
        s->tcp.time = time(NULL);
        s->tcp.state = TCP_CLOSE;
    }
    // Account for data sent/received for closing sessions
    if ((s->tcp.state == TCP_CLOSING || s->tcp.state == TCP_CLOSE) &&
        (s->tcp.sent || s->tcp.received)) {
        account_usage(args, s->tcp.version, IPPROTO_TCP,
                      dest, ntohs(s->tcp.dest), s->tcp.uid, s->tcp.sent, s->tcp.received);
        s->tcp.sent = 0;
        s->tcp.received = 0;
    }

    // Cleanup sessions that have been lingering too long in the CLOSE state
    if (s->tcp.state == TCP_CLOSE && s->tcp.time + TCP_KEEP_TIMEOUT < now)
        return 1;

    return 0;
}

// Function to monitor the state and activity of a TCP session's socket
int monitor_tcp_session(const struct arguments *args, struct ng_session *s, int epoll_fd) {
    int recheck = 0;
    unsigned int events = EPOLLERR; // Default event is error
    // Handle socket in LISTEN state
    if (s->tcp.state == TCP_LISTEN) {
        // Check if the socket is connected
        if (s->tcp.socks5 == SOCKS5_NONE)
            events = events | EPOLLOUT; // Socket is writable
        else
            events = events | EPOLLIN; // Socket has data to read
    } else if (s->tcp.state == TCP_ESTABLISHED || s->tcp.state == TCP_CLOSE_WAIT) {

        // Check if socket has data to read
        if (get_send_window(&s->tcp) > 0)
            events = events | EPOLLIN; // Socket has data to read
        else {
            recheck = 1;

            long long ms = get_ms();
            // Check if it's time to send a keep-alive packet
            if (ms - s->tcp.last_keep_alive > EPOLL_MIN_CHECK) {
                s->tcp.last_keep_alive = ms;
                log_android(ANDROID_LOG_WARN, "Sending keep alive to update send window");
                s->tcp.remote_seq--; // Decrement sequence number for keep-alive
                write_ack(args, &s->tcp);
                s->tcp.remote_seq++; // Increment back the sequence number
            }
        }

        // Check if there's data to send on the socket
        if (s->tcp.forward != NULL) {
            uint32_t buffer_size = (uint32_t) get_receive_buffer(s);
            // Check if there's unsent data in the current segment
            if (s->tcp.forward->seq + s->tcp.forward->sent == s->tcp.remote_seq &&
                s->tcp.forward->len - s->tcp.forward->sent < buffer_size)
                events = events | EPOLLOUT; // Socket is writable
            else
                recheck = 1;
        }
    }
    // Update monitored events for the socket if they've changed
    if (events != s->ev.events) {
        s->ev.events = events;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, s->socket, &s->ev)) {
            s->tcp.state = TCP_CLOSING; // Set state to CLOSING on error
            log_android(ANDROID_LOG_ERROR, "epoll mod tcp error %d: %s", errno, strerror(errno));
        } else
            log_android(ANDROID_LOG_DEBUG, "epoll mod tcp socket %d in %d out %d",
                        s->socket, (events & EPOLLIN) != 0, (events & EPOLLOUT) != 0);
    }

    return recheck;
}

// Function to get the available send window size for the given TCP session
uint32_t get_send_window(const struct tcp_session *cur) {
    // Calculate the difference between the acknowledged sequence and local sequence numbers
    uint32_t behind = (compare_u32(cur->acked, cur->local_seq) <= 0
                       ? cur->local_seq - cur->acked : cur->acked);
    // Calculate the available send window size
    uint32_t window = (behind < cur->send_window ? cur->send_window - behind : 0);
    return window;
}

// Function to get the size of the receive buffer for the given session
int get_receive_buffer(const struct ng_session *cur) {
    if (cur->socket < 0)
        return 0;

    // /proc/sys/net/core/wmem_default
    // Retrieve the size of the send buffer from the system
    int sendbuf = 0;
    int sendbufsize = sizeof(sendbuf);
    if (getsockopt(cur->socket, SOL_SOCKET, SO_SNDBUF, &sendbuf, &sendbufsize) < 0)
        log_android(ANDROID_LOG_WARN, "getsockopt SO_RCVBUF %d: %s", errno, strerror(errno));
    // Default value if send buffer size could not be retrieved
    if (sendbuf == 0)
        sendbuf = 16384; // Safe default

    // Retrieve the size of unsent data in the socket buffer
    int unsent = 0;
    if (ioctl(cur->socket, SIOCOUTQ, &unsent))
        log_android(ANDROID_LOG_WARN, "ioctl SIOCOUTQ %d: %s", errno, strerror(errno));
    // Return the available space in the receive buffer
    return (unsent < sendbuf / 2 ? sendbuf / 2 - unsent : 0);
}

// Function to get the available receive window size for the given session
uint32_t get_receive_window(const struct ng_session *cur) {
    // Calculate the total size of data in the forward queue
    uint32_t toforward = 0;
    struct segment *q = cur->tcp.forward;
    while (q != NULL) {
        toforward += (q->len - q->sent);
        q = q->next;
    }
    // Get available space in the receive buffer
    uint32_t window = (uint32_t) get_receive_buffer(cur);
    // Adjust window size based on TCP receive scaling
    uint32_t max = ((uint32_t) 0xFFFF) << cur->tcp.recv_scale;
    if (window > max)
        window = max;
    // Adjust window size based on data waiting to be forwarded
    window = (toforward < window ? window - toforward : 0);
    if ((window >> cur->tcp.recv_scale) == 0)
        window = 0;

    return window;
}

// Function to handle socket events for the given TCP session
void check_tcp_socket(const struct arguments *args,
                      const struct epoll_event *ev,
                      const int epoll_fd) {
    // Retrieve the session associated with the event
    struct ng_session *s = (struct ng_session *) ev->data.ptr;
    // Store the current state and sequence numbers for comparison later
    int oldstate = s->tcp.state;
    uint32_t oldlocal = s->tcp.local_seq;
    uint32_t oldremote = s->tcp.remote_seq;
    // Buffers for storing IP addresses in string format
    char source[INET6_ADDRSTRLEN + 1];
    char dest[INET6_ADDRSTRLEN + 1];
    // Convert IP addresses from binary to string
    inet_ntop(AF_INET, &s->tcp.saddr.ip4, source, sizeof(source));
    inet_ntop(AF_INET, &s->tcp.daddr.ip4, dest, sizeof(dest));
    // Construct a description of the session for logging
    char session[250];
    sprintf(session, "TCP socket from %s/%u to %s/%u %s loc %u rem %u",
            source, ntohs(s->tcp.source), dest, ntohs(s->tcp.dest),
            strstate(s->tcp.state),
            s->tcp.local_seq - s->tcp.local_start,
            s->tcp.remote_seq - s->tcp.remote_start);

    // Handle socket errors first
    if (ev->events & EPOLLERR) {
        // Update the session's timestamp
        s->tcp.time = time(NULL);
        // Retrieve the specific socket error code
        int serr = 0;
        socklen_t optlen = sizeof(int);
        int err = getsockopt(s->socket, SOL_SOCKET, SO_ERROR, &serr, &optlen);
        if (err < 0)
            // Log the error if getsockopt fails
            log_android(ANDROID_LOG_ERROR, "%s getsockopt error %d: %s",
                        session, errno, strerror(errno));
        else if (serr)
            // Log the error received from getsockopt
            log_android(ANDROID_LOG_ERROR, "%s SO_ERROR %d: %s",
                        session, serr, strerror(serr));
        // Send a TCP RST packet for the session
        write_rst(args, &s->tcp);

        // Handle specific errors for connection refused or host unreachable
        if (0) // This condition will never be met
            if (err >= 0 && (serr == ECONNREFUSED || serr == EHOSTUNREACH)) {
                struct icmp icmp;
                memset(&icmp, 0, sizeof(struct icmp));
                icmp.icmp_type = ICMP_UNREACH;
                if (serr == ECONNREFUSED)
                    icmp.icmp_code = ICMP_UNREACH_PORT;
                else
                    icmp.icmp_code = ICMP_UNREACH_HOST;
                icmp.icmp_cksum = 0;
                icmp.icmp_cksum = ~calc_checksum(0, (const uint8_t *) &icmp, 4);

                struct icmp_session sicmp;
                memset(&sicmp, 0, sizeof(struct icmp_session));
                sicmp.version = s->tcp.version;
                sicmp.saddr.ip4 = (__be32) s->tcp.saddr.ip4;
                sicmp.daddr.ip4 = (__be32) s->tcp.daddr.ip4;

                // Send an ICMP unreachable message
                write_icmp(args, &sicmp, (uint8_t *) &icmp, 8);
            }
    } else {
        // If there are no socket errors, process other socket events
        // Handle the TCP_LISTEN state (connection setup phase)
        if (s->tcp.state == TCP_LISTEN) {
            // Check if there are any SOCKS5 proxy settings
            if (s->tcp.socks5 == SOCKS5_NONE) {
                // If the socket is writable, it means the connection has been established
                if (ev->events & EPOLLOUT) {
                    log_android(ANDROID_LOG_INFO, "%s connected", session);
                    // Handle SOCKS5 setup if required
                    // https://tools.ietf.org/html/rfc1928
                    // https://tools.ietf.org/html/rfc1929
                    // https://en.wikipedia.org/wiki/SOCKS#SOCKS5
                    if (*socks5_addr && socks5_port)
                        s->tcp.socks5 = SOCKS5_HELLO;
                    else
                        s->tcp.socks5 = SOCKS5_CONNECTED;
                }
            } else {
                // If the socket is readable, it means data has been received from the SOCKS5 proxy
                if (ev->events & EPOLLIN) {
                    // Create a buffer to receive SOCKS5 messages
                    uint8_t buffer[32];
                    ssize_t bytes = recv(s->socket, buffer, sizeof(buffer), 0);
                    if (bytes < 0) {
                        // Handle SOCKS5 receive errors
                        log_android(ANDROID_LOG_ERROR, "%s recv SOCKS5 error %d: %s",
                                    session, errno, strerror(errno));
                        write_rst(args, &s->tcp);
                    } else {
                        // Convert the received data to hex for logging
                        char *h = hex(buffer, (const size_t) bytes);
                        log_android(ANDROID_LOG_INFO, "%s recv SOCKS5 %s", session, h);
                        free(h);
                        // Handle the SOCKS5 handshake and authentication process
                        if (s->tcp.socks5 == SOCKS5_HELLO &&
                            bytes == 2 && buffer[0] == 5) {
                            if (buffer[1] == 0)
                                s->tcp.socks5 = SOCKS5_CONNECT;
                            else if (buffer[1] == 2)
                                s->tcp.socks5 = SOCKS5_AUTH;
                            else {
                                s->tcp.socks5 = 0;
                                log_android(ANDROID_LOG_ERROR, "%s SOCKS5 auth %d not supported",
                                            session, buffer[1]);
                                write_rst(args, &s->tcp);
                            }

                        } else if (s->tcp.socks5 == SOCKS5_AUTH &&
                                   bytes == 2 &&
                                   (buffer[0] == 1 || buffer[0] == 5)) {
                            if (buffer[1] == 0) {
                                s->tcp.socks5 = SOCKS5_CONNECT;
                                log_android(ANDROID_LOG_WARN, "%s SOCKS5 auth OK", session);
                            } else {
                                s->tcp.socks5 = 0;
                                log_android(ANDROID_LOG_ERROR, "%s SOCKS5 auth error %d",
                                            session, buffer[1]);
                                write_rst(args, &s->tcp);
                            }

                        } else if (s->tcp.socks5 == SOCKS5_CONNECT &&
                                   bytes == 6 + (s->tcp.version == 4 ? 4 : 16) &&
                                   buffer[0] == 5) {
                            if (buffer[1] == 0) {
                                s->tcp.socks5 = SOCKS5_CONNECTED;
                                log_android(ANDROID_LOG_WARN, "%s SOCKS5 connected", session);
                            } else {
                                s->tcp.socks5 = 0;
                                log_android(ANDROID_LOG_ERROR, "%s SOCKS5 connect error %d",
                                            session, buffer[1]);
                                write_rst(args, &s->tcp);
                                /*
                                    0x00 = request granted
                                    0x01 = general failure
                                    0x02 = connection not allowed by ruleset
                                    0x03 = network unreachable
                                    0x04 = host unreachable
                                    0x05 = connection refused by destination host
                                    0x06 = TTL expired
                                    0x07 = command not supported / protocol error
                                    0x08 = address type not supported
                                 */
                            }

                        } else {
                            s->tcp.socks5 = 0;
                            log_android(ANDROID_LOG_ERROR, "%s recv SOCKS5 state %d",
                                        session, s->tcp.socks5);
                            write_rst(args, &s->tcp);
                        }
                    }
                }
            }
            // Continue the SOCKS5 setup process by sending appropriate messages
            if (s->tcp.socks5 == SOCKS5_HELLO) {
                // Send SOCKS5 initial greeting message
                uint8_t buffer[4] = {5, 2, 0, 2};
                char *h = hex(buffer, sizeof(buffer));
                log_android(ANDROID_LOG_INFO, "%s sending SOCKS5 hello: %s",
                            session, h);
                free(h);
                ssize_t sent = send(s->socket, buffer, sizeof(buffer), MSG_NOSIGNAL);
                if (sent < 0) {
                    // Handle errors when sending the SOCKS5 greeting
                    log_android(ANDROID_LOG_ERROR, "%s send SOCKS5 hello error %d: %s",
                                session, errno, strerror(errno));
                    write_rst(args, &s->tcp);
                }

            } else if (s->tcp.socks5 == SOCKS5_AUTH) {
                // Send SOCKS5 authentication message
                uint8_t ulen = strlen(socks5_username);
                uint8_t plen = strlen(socks5_password);
                uint8_t buffer[512];
                *(buffer + 0) = 1; // Version
                *(buffer + 1) = ulen;
                memcpy(buffer + 2, socks5_username, ulen);
                *(buffer + 2 + ulen) = plen;
                memcpy(buffer + 2 + ulen + 1, socks5_password, plen);

                size_t len = 2 + ulen + 1 + plen;

                char *h = hex(buffer, len);
                log_android(ANDROID_LOG_INFO, "%s sending SOCKS5 auth: %s",
                            session, h);
                free(h);
                ssize_t sent = send(s->socket, buffer, len, MSG_NOSIGNAL);
                if (sent < 0) {
                    // Handle errors when sending the SOCKS5 authentication
                    log_android(ANDROID_LOG_ERROR,
                                "%s send SOCKS5 connect error %d: %s",
                                session, errno, strerror(errno));
                    write_rst(args, &s->tcp);
                }

            } else if (s->tcp.socks5 == SOCKS5_CONNECT) {
                // Send SOCKS5 connection request message
                uint8_t buffer[22];
                *(buffer + 0) = 5; // Version
                *(buffer + 1) = 1; // Command (connect)
                *(buffer + 2) = 0; // Reserved
                *(buffer + 3) = (uint8_t) (s->tcp.version == 4 ? 1 : 4);
                memcpy(buffer + 4, &s->tcp.daddr.ip4, 4);
                *((__be16 *) (buffer + 4 + 4)) = s->tcp.dest;

                size_t len = (s->tcp.version == 4 ? 10 : 22);

                char *h = hex(buffer, len);
                log_android(ANDROID_LOG_INFO, "%s sending SOCKS5 connect: %s",
                            session, h);
                free(h);
                ssize_t sent = send(s->socket, buffer, len, MSG_NOSIGNAL);
                if (sent < 0) {
                    // Handle errors when sending the SOCKS5 connection request
                    log_android(ANDROID_LOG_ERROR,
                                "%s send SOCKS5 connect error %d: %s",
                                session, errno, strerror(errno));
                    write_rst(args, &s->tcp);
                }

            } else if (s->tcp.socks5 == SOCKS5_CONNECTED) {
                // Process the connected state of the SOCKS5 proxy
                s->tcp.remote_seq++; // remote SYN
                if (write_syn_ack(args, &s->tcp) >= 0) {
                    s->tcp.time = time(NULL);
                    s->tcp.local_seq++; // local SYN
                    s->tcp.state = TCP_SYN_RECV;
                }
            }
        } else {
            // Handle states other than TCP_LISTEN
            // Always forward data
            int fwd = 0;
            if (ev->events & EPOLLOUT) {
                // Forward data to the target
                uint32_t buffer_size = (uint32_t) get_receive_buffer(s);
                while (s->tcp.forward != NULL &&
                       s->tcp.forward->seq + s->tcp.forward->sent == s->tcp.remote_seq &&
                       s->tcp.forward->len - s->tcp.forward->sent < buffer_size) {
                    log_android(ANDROID_LOG_DEBUG, "%s fwd %u...%u sent %u",
                                session,
                                s->tcp.forward->seq - s->tcp.remote_start,
                                s->tcp.forward->seq + s->tcp.forward->len - s->tcp.remote_start,
                                s->tcp.forward->sent);
                    // Send the data to the socket
                    ssize_t sent = send(s->socket,
                                        s->tcp.forward->data + s->tcp.forward->sent,
                                        s->tcp.forward->len - s->tcp.forward->sent,
                                        (unsigned int) (MSG_NOSIGNAL | (s->tcp.forward->psh
                                                                        ? 0
                                                                        : MSG_MORE)));
                    if (sent < 0) {
                        // Handle errors during data forwarding
                        log_android(ANDROID_LOG_ERROR, "%s send error %d: %s",
                                    session, errno, strerror(errno));
                        if (errno == EINTR || errno == EAGAIN) {
                            // Retry later
                            break;
                        } else {
                            write_rst(args, &s->tcp);
                            break;
                        }
                    } else {
                        fwd = 1;
                        buffer_size -= sent;
                        s->tcp.sent += sent;
                        s->tcp.forward->sent += sent;
                        s->tcp.remote_seq = s->tcp.forward->seq + s->tcp.forward->sent;
                        // Free the forwarded data if everything has been sent
                        if (s->tcp.forward->len == s->tcp.forward->sent) {
                            struct segment *p = s->tcp.forward;
                            s->tcp.forward = s->tcp.forward->next;
                            free(p->data);
                            free(p);
                        } else {
                            // Log partial data send
                            log_android(ANDROID_LOG_WARN,
                                        "%s partial send %u/%u",
                                        session, s->tcp.forward->sent, s->tcp.forward->len);
                            break;
                        }
                    }
                }

                // Log the buffered data
                struct segment *seg = s->tcp.forward;
                while (seg != NULL) {
                    log_android(ANDROID_LOG_WARN, "%s queued %u...%u sent %u",
                                session,
                                seg->seq - s->tcp.remote_start,
                                seg->seq + seg->len - s->tcp.remote_start,
                                seg->sent);
                    seg = seg->next;
                }
            }

            // Get the receive window size
            uint32_t window = get_receive_window(s);
            uint32_t prev = s->tcp.recv_window;
            s->tcp.recv_window = window;
            if ((prev == 0 && window > 0) || (prev > 0 && window == 0))
                log_android(ANDROID_LOG_WARN, "%s recv window %u > %u",
                            session, prev, window);

            // Acknowledge the forwarded data
            if (fwd || (prev == 0 && window > 0)) {
                if (fwd && s->tcp.forward == NULL && s->tcp.state == TCP_CLOSE_WAIT) {
                    log_android(ANDROID_LOG_WARN, "%s confirm FIN", session);
                    s->tcp.remote_seq++; // remote FIN
                }
                if (write_ack(args, &s->tcp) >= 0)
                    s->tcp.time = time(NULL);
            }
            // Handle established or waiting-for-close states
            if (s->tcp.state == TCP_ESTABLISHED || s->tcp.state == TCP_CLOSE_WAIT) {
                // Send window can be changed in the mean time
                // Check if the socket is readable
                uint32_t send_window = get_send_window(&s->tcp);
                if ((ev->events & EPOLLIN) && send_window > 0) {
                    s->tcp.time = time(NULL);

                    uint32_t buffer_size = (send_window > s->tcp.mss
                                            ? s->tcp.mss : send_window);
                    uint8_t *buffer = malloc(buffer_size);
                    ssize_t bytes = recv(s->socket, buffer, (size_t) buffer_size, 0);
                    if (bytes < 0) {
                        // Handle socket read errors
                        log_android(ANDROID_LOG_ERROR, "%s recv error %d: %s",
                                    session, errno, strerror(errno));

                        if (errno != EINTR && errno != EAGAIN)
                            write_rst(args, &s->tcp);
                    } else if (bytes == 0) {
                        // Handle socket closure
                        log_android(ANDROID_LOG_WARN, "%s recv eof", session);
                        // Handle different TCP states upon receiving EOF
                        if (s->tcp.forward == NULL) {
                            if (write_fin_ack(args, &s->tcp) >= 0) {
                                log_android(ANDROID_LOG_WARN, "%s FIN sent", session);
                                s->tcp.local_seq++; // local FIN
                            }

                            if (s->tcp.state == TCP_ESTABLISHED)
                                s->tcp.state = TCP_FIN_WAIT1;
                            else if (s->tcp.state == TCP_CLOSE_WAIT)
                                s->tcp.state = TCP_LAST_ACK;
                            else
                                log_android(ANDROID_LOG_ERROR, "%s invalid close", session);
                        } else {
                            // There was still data to send
                            log_android(ANDROID_LOG_ERROR, "%s close with queue", session);
                            write_rst(args, &s->tcp);
                        }
                        // Close the socket
                        if (close(s->socket))
                            log_android(ANDROID_LOG_ERROR, "%s close error %d: %s",
                                        session, errno, strerror(errno));
                        s->socket = -1;

                    } else {
                        // Handle the received data
                        log_android(ANDROID_LOG_DEBUG, "%s recv bytes %d", session, bytes);
                        s->tcp.received += bytes;
                        // Forward the data to the TUN interface
                        if (write_data(args, &s->tcp, buffer, (size_t) bytes) >= 0)
                            s->tcp.local_seq += bytes;
                    }
                    free(buffer);
                }
            }
        }
    }
    // Log the session state if there was a change
    if (s->tcp.state != oldstate || s->tcp.local_seq != oldlocal ||
        s->tcp.remote_seq != oldremote)
        log_android(ANDROID_LOG_DEBUG, "%s new state", session);
}

// Function to handle and process TCP packets
jboolean handle_tcp(const struct arguments *args,
                    const uint8_t *pkt, size_t length,
                    const uint8_t *payload,
                    int uid, int allowed, struct allowed *redirect,
                    const int epoll_fd) {
    // Extract the IP version from the packet header
    const uint8_t version = (*pkt) >> 4;
    // Cast the packet to IPv4 header for processing
    const struct iphdr *ip4 = (struct iphdr *) pkt;
    // Cast the packet to IPv6 header for processing
    const struct ip6_hdr *ip6 = (struct ip6_hdr *) pkt;
    // Cast the payload to TCP header to extract details
    const struct tcphdr *tcphdr = (struct tcphdr *) payload;
    // Calculate TCP option length
    const uint8_t tcpoptlen = (uint8_t) ((tcphdr->doff - 5) * 4);
    // Determine the start of TCP options within the packet
    const uint8_t *tcpoptions = payload + sizeof(struct tcphdr);
    // Calculate the start of the actual data after the TCP header and options
    const uint8_t *data = payload + sizeof(struct tcphdr) + tcpoptlen;
    // Calculate the length of the actual data
    const uint16_t datalen = (const uint16_t) (length - (data - pkt));

    // Search for an existing session that matches the current packet details
    struct ng_session *cur = args->ctx->ng_session;
    while (cur != NULL &&
           !(cur->protocol == IPPROTO_TCP &&
             cur->tcp.version == version &&
             cur->tcp.source == tcphdr->source && cur->tcp.dest == tcphdr->dest &&
             (version == 4 ? cur->tcp.saddr.ip4 == ip4->saddr &&
                             cur->tcp.daddr.ip4 == ip4->daddr
                           : memcmp(&cur->tcp.saddr.ip6, &ip6->ip6_src, 16) == 0 &&
                             memcmp(&cur->tcp.daddr.ip6, &ip6->ip6_dst, 16) == 0)))
        cur = cur->next;

    // Prepare logging by converting the source and destination IP addresses to human-readable strings
    char source[INET6_ADDRSTRLEN + 1];
    char dest[INET6_ADDRSTRLEN + 1];
    inet_ntop(AF_INET, &ip4->saddr, source, sizeof(source));
    inet_ntop(AF_INET, &ip4->daddr, dest, sizeof(dest));

    // Prepare a string to represent the TCP flags for logging purposes
    char flags[10];
    int flen = 0;
    if (tcphdr->syn)
        flags[flen++] = 'S';
    if (tcphdr->ack)
        flags[flen++] = 'A';
    if (tcphdr->psh)
        flags[flen++] = 'P';
    if (tcphdr->fin)
        flags[flen++] = 'F';
    if (tcphdr->rst)
        flags[flen++] = 'R';
    if (tcphdr->urg)
        flags[flen++] = 'U';
    flags[flen] = 0;
    // Create a detailed logging string for this TCP packet
    char packet[250];
    sprintf(packet,
            "TCP %s %s/%u > %s/%u seq %u ack %u data %u win %u uid %d",
            flags,
            source, ntohs(tcphdr->source),
            dest, ntohs(tcphdr->dest),
            ntohl(tcphdr->seq) - (cur == NULL ? 0 : cur->tcp.remote_start),
            tcphdr->ack ? ntohl(tcphdr->ack_seq) - (cur == NULL ? 0 : cur->tcp.local_start) : 0,
            datalen, ntohs(tcphdr->window), uid);
    // Log the packet details
    log_android(tcphdr->urg ? ANDROID_LOG_WARN : ANDROID_LOG_DEBUG, packet);

    // If the URG flag is set, drop the data and return
    if (tcphdr->urg)
        return 1;

    // Check if a session exists for the current packet
    if (cur == NULL) {
        if (tcphdr->syn) {
            // Decode and extract TCP options
            // http://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml#tcp-parameters-1
            uint16_t mss = get_default_mss(version);
            uint8_t ws = 0;
            int optlen = tcpoptlen;
            uint8_t *options = (uint8_t *) tcpoptions;
            while (optlen > 0) {
                uint8_t kind = *options;
                uint8_t len = *(options + 1);
                if (kind == 0) // End of options list
                    break;

                if (kind == 2 && len == 4)
                    mss = ntohs(*((uint16_t *) (options + 2)));

                else if (kind == 3 && len == 3)
                    ws = *(options + 2);

                if (kind == 1) {
                    optlen--;
                    options++;
                } else {
                    optlen -= len;
                    options += len;
                }
            }
            // Log the new session details
            log_android(ANDROID_LOG_WARN, "%s new session mss %u ws %u window %u",
                        packet, mss, ws, ntohs(tcphdr->window) << ws);

            // Create and initialize a new session for this TCP connection
            struct ng_session *s = malloc(sizeof(struct ng_session));
            s->protocol = IPPROTO_TCP;

            s->tcp.time = time(NULL);
            s->tcp.uid = uid;
            s->tcp.version = version;
            s->tcp.mss = mss;
            s->tcp.recv_scale = ws;
            s->tcp.send_scale = ws;
            s->tcp.send_window = ((uint32_t) ntohs(tcphdr->window)) << s->tcp.send_scale;
            s->tcp.remote_seq = ntohl(tcphdr->seq); // ISN remote
            s->tcp.local_seq = (uint32_t) rand(); // ISN local
            s->tcp.remote_start = s->tcp.remote_seq;
            s->tcp.local_start = s->tcp.local_seq;
            s->tcp.acked = 0;
            s->tcp.last_keep_alive = 0;
            s->tcp.sent = 0;
            s->tcp.received = 0;

            s->tcp.saddr.ip4 = (__be32) ip4->saddr;
            s->tcp.daddr.ip4 = (__be32) ip4->daddr;


            s->tcp.source = tcphdr->source;
            s->tcp.dest = tcphdr->dest;
            s->tcp.state = TCP_LISTEN;
            s->tcp.socks5 = SOCKS5_NONE;
            s->tcp.forward = NULL;
            s->next = NULL;
            // If there's data in the SYN packet, queue it for forwarding
            if (datalen) {
                log_android(ANDROID_LOG_WARN, "%s SYN data", packet);
                s->tcp.forward = malloc(sizeof(struct segment));
                s->tcp.forward->seq = s->tcp.remote_seq;
                s->tcp.forward->len = datalen;
                s->tcp.forward->sent = 0;
                s->tcp.forward->psh = tcphdr->psh;
                s->tcp.forward->data = malloc(datalen);
                memcpy(s->tcp.forward->data, data, datalen);
                s->tcp.forward->next = NULL;
            }

            // Open a socket for this new session
            s->socket = open_tcp_socket(args, &s->tcp, redirect);
            if (s->socket < 0) {
                // If socket opening fails, remote might retry
                free(s);
                return 0;
            }

            s->tcp.recv_window = get_receive_window(s);
            // Log the socket details
            log_android(ANDROID_LOG_DEBUG, "TCP socket %d lport %d",
                        s->socket, get_local_port(s->socket));

            // Monitor the socket for events using epoll
            memset(&s->ev, 0, sizeof(struct epoll_event));
            s->ev.events = EPOLLOUT | EPOLLERR;
            s->ev.data.ptr = s;
            if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, s->socket, &s->ev))
                log_android(ANDROID_LOG_ERROR, "epoll add tcp error %d: %s",
                            errno, strerror(errno));
            // Link the new session to the list of active sessions
            s->next = args->ctx->ng_session;
            args->ctx->ng_session = s;
            // If the packet is not allowed, send a reset
            if (!allowed) {
                log_android(ANDROID_LOG_WARN, "%s resetting blocked session", packet);
                write_rst(args, &s->tcp);
            }
        } else {
            // If no session is found and the packet isn't a SYN, log it as unknown
            log_android(ANDROID_LOG_WARN, "%s unknown session", packet);
            // Create a temporary session to send a reset to the remote endpoint
            struct tcp_session rst;
            memset(&rst, 0, sizeof(struct tcp_session));
            rst.version = 4;
            rst.local_seq = ntohl(tcphdr->ack_seq);
            rst.remote_seq = ntohl(tcphdr->seq) + datalen + (tcphdr->syn || tcphdr->fin ? 1 : 0);

            rst.saddr.ip4 = (__be32) ip4->saddr;
            rst.daddr.ip4 = (__be32) ip4->daddr;


            rst.source = tcphdr->source;
            rst.dest = tcphdr->dest;
            // Send a reset for this unknown session
            write_rst(args, &rst);
            return 0;
        }
    } else {
        // If a session is found, process the packet and update the session state accordingly
        char session[250];
        sprintf(session,
                "%s %s loc %u rem %u acked %u",
                packet,
                strstate(cur->tcp.state),
                cur->tcp.local_seq - cur->tcp.local_start,
                cur->tcp.remote_seq - cur->tcp.remote_start,
                cur->tcp.acked - cur->tcp.local_start);

        // Check the current session state
        if (cur->tcp.state == TCP_CLOSING || cur->tcp.state == TCP_CLOSE) {
            // If the session is in a closed or closing state, send a reset
            log_android(ANDROID_LOG_WARN, "%s was closed", session);
            write_rst(args, &cur->tcp);
            return 0;
        } else {
            int oldstate = cur->tcp.state;
            uint32_t oldlocal = cur->tcp.local_seq;
            uint32_t oldremote = cur->tcp.remote_seq;

            log_android(ANDROID_LOG_DEBUG, "%s handling", session);
            // Update the session's last activity timestamp and advertised window size
            cur->tcp.time = time(NULL);
            cur->tcp.send_window = ntohs(tcphdr->window) << cur->tcp.send_scale;

            // Do not change the order of the conditions

            // Queue data to forward
            if (datalen) {
                if (cur->socket < 0) {
                    log_android(ANDROID_LOG_ERROR, "%s data while local closed", session);
                    write_rst(args, &cur->tcp);
                    return 0;
                }
                if (cur->tcp.state == TCP_CLOSE_WAIT) {
                    log_android(ANDROID_LOG_ERROR, "%s data while remote closed", session);
                    write_rst(args, &cur->tcp);
                    return 0;
                }
                queue_tcp(args, tcphdr, session, &cur->tcp, data, datalen);
            }
            // Process the TCP packet flags and update the session state accordingly
            // Note: the order of these checks is critical for correct behavior
            if (tcphdr->rst /* +ACK */) {
                // If the RST flag is set, mark the session as closing
                // http://tools.ietf.org/html/rfc1122#page-87
                log_android(ANDROID_LOG_WARN, "%s received reset", session);
                cur->tcp.state = TCP_CLOSING;
                return 0;
            } else {
                if (!tcphdr->ack || ntohl(tcphdr->ack_seq) == cur->tcp.local_seq) {
                    if (tcphdr->syn) {
                        // If a SYN is received for an existing session, it's a repeated SYN
                        log_android(ANDROID_LOG_WARN, "%s repeated SYN", session);
                        // The socket might not be opened yet
                    } else if (tcphdr->fin /* +ACK */) {
                        // Handle the FIN flag based on the current session state
                        if (cur->tcp.state == TCP_ESTABLISHED) {
                            log_android(ANDROID_LOG_WARN, "%s FIN received", session);
                            if (cur->tcp.forward == NULL) {
                                cur->tcp.remote_seq++; // remote FIN
                                if (write_ack(args, &cur->tcp) >= 0)
                                    cur->tcp.state = TCP_CLOSE_WAIT;
                            } else
                                cur->tcp.state = TCP_CLOSE_WAIT;
                        } else if (cur->tcp.state == TCP_CLOSE_WAIT) {
                            log_android(ANDROID_LOG_WARN, "%s repeated FIN", session);
                            // The socket might not be closed yet
                        } else if (cur->tcp.state == TCP_FIN_WAIT1) {
                            log_android(ANDROID_LOG_WARN, "%s last ACK", session);
                            cur->tcp.remote_seq++; // remote FIN
                            if (write_ack(args, &cur->tcp) >= 0)
                                cur->tcp.state = TCP_CLOSE;
                        } else {
                            log_android(ANDROID_LOG_ERROR, "%s invalid FIN", session);
                            return 0;
                        }

                    } else if (tcphdr->ack) {
                        // Handle the ACK flag and update the session state
                        cur->tcp.acked = ntohl(tcphdr->ack_seq);

                        if (cur->tcp.state == TCP_SYN_RECV)
                            cur->tcp.state = TCP_ESTABLISHED;

                        else if (cur->tcp.state == TCP_ESTABLISHED) {
                            // Do nothing
                        } else if (cur->tcp.state == TCP_LAST_ACK)
                            cur->tcp.state = TCP_CLOSING;

                        else if (cur->tcp.state == TCP_CLOSE_WAIT) {
                            // ACK after FIN/ACK
                        } else if (cur->tcp.state == TCP_FIN_WAIT1) {
                            // Do nothing
                        } else {
                            log_android(ANDROID_LOG_ERROR, "%s invalid state", session);
                            return 0;
                        }
                    } else {
                        log_android(ANDROID_LOG_ERROR, "%s unknown packet", session);
                        return 0;
                    }
                } else {
                    // Handle out-of-order or unexpected ACKs
                    uint32_t ack = ntohl(tcphdr->ack_seq);
                    if ((uint32_t) (ack + 1) == cur->tcp.local_seq) {
                        // Keep alive
                        if (cur->tcp.state == TCP_ESTABLISHED) {
                            int on = 1;
                            if (setsockopt(cur->socket, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on)))
                                log_android(ANDROID_LOG_ERROR,
                                            "%s setsockopt SO_KEEPALIVE error %d: %s",
                                            session, errno, strerror(errno));
                            else
                                log_android(ANDROID_LOG_WARN, "%s enabled keep alive", session);
                        } else
                            log_android(ANDROID_LOG_WARN, "%s keep alive", session);

                    } else if (compare_u32(ack, cur->tcp.local_seq) < 0) {
                        if (compare_u32(ack, cur->tcp.acked) <= 0)
                            log_android(
                                    ack == cur->tcp.acked ? ANDROID_LOG_WARN : ANDROID_LOG_ERROR,
                                    "%s repeated ACK %u/%u",
                                    session,
                                    ack - cur->tcp.local_start,
                                    cur->tcp.acked - cur->tcp.local_start);
                        else {
                            log_android(ANDROID_LOG_WARN, "%s previous ACK %u",
                                        session, ack - cur->tcp.local_seq);
                            cur->tcp.acked = ack;
                        }

                        return 1;
                    } else {
                        log_android(ANDROID_LOG_ERROR, "%s future ACK", session);
                        write_rst(args, &cur->tcp);
                        return 0;
                    }
                }
            }
            // Log changes in session state or sequence numbers
            if (cur->tcp.state != oldstate ||
                cur->tcp.local_seq != oldlocal ||
                cur->tcp.remote_seq != oldremote)
                log_android(ANDROID_LOG_INFO, "%s > %s loc %u rem %u",
                            session,
                            strstate(cur->tcp.state),
                            cur->tcp.local_seq - cur->tcp.local_start,
                            cur->tcp.remote_seq - cur->tcp.remote_start);
        }
    }

    return 1;
}

// Function to queue TCP segments for forwarding
void queue_tcp(const struct arguments *args,
               const struct tcphdr *tcphdr,
               const char *session, struct tcp_session *cur,
               const uint8_t *data, uint16_t datalen) {
    // Convert the sequence number from network byte order to host byte order
    uint32_t seq = ntohl(tcphdr->seq);
    // Check if the sequence number of the segment is less than the expected remote sequence number
    if (compare_u32(seq, cur->remote_seq) < 0)
        // Log a warning if the segment was already forwarded
        log_android(ANDROID_LOG_WARN, "%s already forwarded %u..%u",
                    session,
                    seq - cur->remote_start, seq + datalen - cur->remote_start);
    else {
        // Pointers to traverse and manage the linked list of segments
        struct segment *p = NULL;
        struct segment *s = cur->forward;
        // Traverse the linked list to find the right position to insert the segment
        while (s != NULL && compare_u32(s->seq, seq) < 0) {
            p = s;
            s = s->next;
        }
        // If there's no segment with the same sequence number or a greater one, insert a new segment
        if (s == NULL || compare_u32(s->seq, seq) > 0) {
            log_android(ANDROID_LOG_DEBUG, "%s queuing %u...%u",
                        session,
                        seq - cur->remote_start, seq + datalen - cur->remote_start);
            // Allocate memory for the new segment
            struct segment *n = malloc(sizeof(struct segment));
            n->seq = seq;
            n->len = datalen;
            n->sent = 0;
            n->psh = tcphdr->psh;
            n->data = malloc(datalen);
            // Copy the segment data
            memcpy(n->data, data, datalen);
            n->next = s;
            // Insert the new segment in the linked list
            if (p == NULL)
                cur->forward = n;
            else
                p->next = n;
        } else if (s != NULL && s->seq == seq) {
            // If there's already a segment with the same sequence number
            if (s->len == datalen)
                // Log a warning if the segment was already queued with the same length
                log_android(ANDROID_LOG_WARN, "%s segment already queued %u..%u",
                            session,
                            s->seq - cur->remote_start, s->seq + s->len - cur->remote_start);
            else if (s->len < datalen) {
                // Log a warning if the segment in the queue is smaller than the current segment
                log_android(ANDROID_LOG_WARN, "%s segment smaller %u..%u > %u",
                            session,
                            s->seq - cur->remote_start, s->seq + s->len - cur->remote_start,
                            s->seq + datalen - cur->remote_start);
                // Replace the segment data with the current segment's data
                free(s->data);
                s->data = malloc(datalen);
                memcpy(s->data, data, datalen);
            } else
                // Log an error if the segment in the queue is larger than the current segment
                log_android(ANDROID_LOG_ERROR, "%s segment larger %u..%u < %u",
                            session,
                            s->seq - cur->remote_start, s->seq + s->len - cur->remote_start,
                            s->seq + datalen - cur->remote_start);
        }
    }
}
// Function to open a TCP socket for the given session or redirect
int open_tcp_socket(const struct arguments *args,
                    const struct tcp_session *cur, const struct allowed *redirect) {
    int sock; // Socket file descriptor
    int version; // IP version (IPv4 or IPv6)
    // Determine IP version based on SOCKS5 proxy or current session
    if (redirect == NULL) {
        if (*socks5_addr && socks5_port)
            version = (strstr(socks5_addr, ":") == NULL ? 4 : 6);
        else
            version = cur->version;
    } else
        version = (strstr(redirect->raddr, ":") == NULL ? 4 : 6);

    // Create a TCP socket based on the determined IP version
    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        log_android(ANDROID_LOG_ERROR, "socket error %d: %s", errno, strerror(errno));
        return -1;
    }

    // Protect the socket from VPN (usually applicable to Android apps)
    if (protect_socket(args, sock) < 0)
        return -1;

    // Set the socket to non-blocking mode
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        log_android(ANDROID_LOG_ERROR, "fcntl socket O_NONBLOCK error %d: %s",
                    errno, strerror(errno));
        return -1;
    }

    // Define the destination address for the connection
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
    if (redirect == NULL) {
        if (*socks5_addr && socks5_port) {
            log_android(ANDROID_LOG_WARN, "TCP%d SOCKS5 to %s/%u",
                        version, socks5_addr, socks5_port);

            addr4.sin_family = AF_INET;
            inet_pton(AF_INET, socks5_addr, &addr4.sin_addr);
            addr4.sin_port = htons(socks5_port);

        } else {
            addr4.sin_family = AF_INET;
            addr4.sin_addr.s_addr = (__be32) cur->daddr.ip4;
            addr4.sin_port = cur->dest;
        }
    } else {
        log_android(ANDROID_LOG_WARN, "TCP%d redirect to %s/%u",
                    version, redirect->raddr, redirect->rport);

        addr4.sin_family = AF_INET;
        inet_pton(AF_INET, redirect->raddr, &addr4.sin_addr);
        addr4.sin_port = htons(redirect->rport);

    }

    // Attempt to connect to the determined destination address
    int err = connect(sock,
                      (version == 4 ? (const struct sockaddr *) &addr4
                                    : (const struct sockaddr *) &addr6),
                      (socklen_t) (version == 4
                                   ? sizeof(struct sockaddr_in)
                                   : sizeof(struct sockaddr_in6)));
    if (err < 0 && errno != EINPROGRESS) {
        log_android(ANDROID_LOG_ERROR, "connect error %d: %s", errno, strerror(errno));
        return -1;
    }

    return sock;
}
// Function to send a TCP SYN-ACK packet
int write_syn_ack(const struct arguments *args, struct tcp_session *cur) {
    if (write_tcp(args, cur, NULL, 0, 1, 1, 0, 0) < 0) {
        cur->state = TCP_CLOSING;
        return -1;
    }
    return 0;
}
// Function to send a TCP ACK packet
int write_ack(const struct arguments *args, struct tcp_session *cur) {
    if (write_tcp(args, cur, NULL, 0, 0, 1, 0, 0) < 0) {
        cur->state = TCP_CLOSING;
        return -1;
    }
    return 0;
}
// Function to send a data segment over TCP
int write_data(const struct arguments *args, struct tcp_session *cur,
               const uint8_t *buffer, size_t length) {
    if (write_tcp(args, cur, buffer, length, 0, 1, 0, 0) < 0) {
        cur->state = TCP_CLOSING;
        return -1;
    }
    return 0;
}
// Function to send a TCP FIN-ACK packet
int write_fin_ack(const struct arguments *args, struct tcp_session *cur) {
    if (write_tcp(args, cur, NULL, 0, 0, 1, 1, 0) < 0) {
        cur->state = TCP_CLOSING;
        return -1;
    }
    return 0;
}
// Function to send a TCP RST (reset) packet
void write_rst(const struct arguments *args, struct tcp_session *cur) {
    // https://www.snellman.net/blog/archive/2016-02-01-tcp-rst/
    // Acknowledge the SYN if the current state is LISTEN
    int ack = 0;
    if (cur->state == TCP_LISTEN) {
        ack = 1;
        cur->remote_seq++; // SYN
    }
    write_tcp(args, cur, NULL, 0, 0, ack, 0, 1);
    if (cur->state != TCP_CLOSE)
        cur->state = TCP_CLOSING;
}

// Function to write TCP data with the given flags and data to a TUN device
ssize_t write_tcp(const struct arguments *args, const struct tcp_session *cur,
                  const uint8_t *data, size_t datalen,
                  int syn, int ack, int fin, int rst) {
    size_t len; // Total packet length
    u_int8_t *buffer; // The complete packet buffer
    struct tcphdr *tcp; // TCP header pointer
    uint16_t csum; // Checksum value
    char source[INET6_ADDRSTRLEN + 1]; // Source IP in string format
    char dest[INET6_ADDRSTRLEN + 1]; // Destination IP in string format

    // Variables for TCP options
    int optlen = (syn ? 4 + 3 + 1 : 0); // Length of TCP options (only if SYN flag is set)
    uint8_t *options; // Pointer to options
    // Check if we're working with IPv4
    if (cur->version == 4) {
        // Calculate total packet length
        len = sizeof(struct iphdr) + sizeof(struct tcphdr) + optlen + datalen;
        buffer = malloc(len); // Allocate buffer for the packet
        struct iphdr *ip4 = (struct iphdr *) buffer;
        tcp = (struct tcphdr *) (buffer + sizeof(struct iphdr));
        options = buffer + sizeof(struct iphdr) + sizeof(struct tcphdr);
        // Copy data if present
        if (datalen)
            memcpy(buffer + sizeof(struct iphdr) + sizeof(struct tcphdr) + optlen, data, datalen);

        // Build the IPv4 header
        memset(ip4, 0, sizeof(struct iphdr));
        ip4->version = 4;
        ip4->ihl = sizeof(struct iphdr) >> 2;
        ip4->tot_len = htons(len);
        ip4->ttl = IPDEFTTL;
        ip4->protocol = IPPROTO_TCP;
        ip4->saddr = cur->daddr.ip4;
        ip4->daddr = cur->saddr.ip4;

        // Calculate IPv4 header checksum
        ip4->check = ~calc_checksum(0, (uint8_t *) ip4, sizeof(struct iphdr));

        // Prepare to calculate TCP checksum for IPv4
        struct ippseudo pseudo;
        memset(&pseudo, 0, sizeof(struct ippseudo));
        pseudo.ippseudo_src.s_addr = (__be32) ip4->saddr;
        pseudo.ippseudo_dst.s_addr = (__be32) ip4->daddr;
        pseudo.ippseudo_p = ip4->protocol;
        pseudo.ippseudo_len = htons(sizeof(struct tcphdr) + optlen + datalen);
        csum = calc_checksum(0, (uint8_t *) &pseudo, sizeof(struct ippseudo));
    }


    // Build the TCP header
    memset(tcp, 0, sizeof(struct tcphdr));
    tcp->source = cur->dest;
    tcp->dest = cur->source;
    tcp->seq = htonl(cur->local_seq);
    tcp->ack_seq = htonl((uint32_t) (cur->remote_seq));
    tcp->doff = (__u16) ((sizeof(struct tcphdr) + optlen) >> 2);
    tcp->syn = (__u16) syn;
    tcp->ack = (__u16) ack;
    tcp->fin = (__u16) fin;
    tcp->rst = (__u16) rst;
    tcp->window = htons(cur->recv_window >> cur->recv_scale);
    // If ACK flag is not set, reset ACK sequence number
    if (!tcp->ack)
        tcp->ack_seq = 0;

    // Set TCP options if SYN flag is set
    if (syn) {
        *(options) = 2; // Maximum Segment Size (MSS) option kind
        *(options + 1) = 4; // MSS option length
        *((uint16_t *) (options + 2)) = get_default_mss(cur->version); // Default MSS value
        *(options + 4) = 3; // Window scale option kind
        *(options + 5) = 3; // Window scale option length
        *(options + 6) = cur->recv_scale; // Current receive window scale
        *(options + 7) = 0; // End of options list (and padding)
    }

    // Continue calculating the TCP checksum
    csum = calc_checksum(csum, (uint8_t *) tcp, sizeof(struct tcphdr));
    csum = calc_checksum(csum, options, (size_t) optlen);
    csum = calc_checksum(csum, data, datalen);
    tcp->check = ~csum; // Finalize the TCP checksum

    // Convert source and destination IPs to string for logging
    inet_ntop(cur->version == 4 ? AF_INET : AF_INET6,
              cur->version == 4 ? (const void *) &cur->saddr.ip4 : (const void *) &cur->saddr.ip6,
              source, sizeof(source));
    inet_ntop(cur->version == 4 ? AF_INET : AF_INET6,
              cur->version == 4 ? (const void *) &cur->daddr.ip4 : (const void *) &cur->daddr.ip6,
              dest, sizeof(dest));

    // Log the outgoing TCP packet details
    log_android(ANDROID_LOG_DEBUG,
                "TCP sending%s%s%s%s to tun %s/%u seq %u ack %u data %u",
                (tcp->syn ? " SYN" : ""),
                (tcp->ack ? " ACK" : ""),
                (tcp->fin ? " FIN" : ""),
                (tcp->rst ? " RST" : ""),
                dest, ntohs(tcp->dest),
                ntohl(tcp->seq) - cur->local_start,
                ntohl(tcp->ack_seq) - cur->remote_start,
                datalen);
    // Send the constructed TCP packet to the TUN device
    ssize_t res = write(args->tun, buffer, len);
    free(buffer);  // Free the allocated buffer
    if (res != len) {
        log_android(ANDROID_LOG_ERROR, "TCP write %d/%d", res, len);
        return -1;
    }
    return res; // Return the number of bytes written
}
