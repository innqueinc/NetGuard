#include "netguard.h"

// Function to get the timeout for a given UDP session.
int get_udp_timeout(const struct udp_session *u, int sessions, int maxsessions) {
    // Determine the timeout based on the destination port. If it's port 53 (DNS), use a specific timeout; otherwise, use a default timeout.
    int timeout = (ntohs(u->dest) == 53 ? UDP_TIMEOUT_53 : UDP_TIMEOUT_ANY);
    // Adjust the timeout based on the current number of sessions relative to the maximum allowed sessions.
    int scale = 100 - sessions * 100 / maxsessions;
    timeout = timeout * scale / 100;
    // Return the calculated timeout.
    return timeout;
}

// Function to check the state and timeouts of a given UDP session.
int check_udp_session(const struct arguments *args, struct ng_session *s,
                      int sessions, int maxsessions) {
    // Get the current time.
    time_t now = time(NULL);
    // Buffers to store the source and destination IP addresses as strings.
    char source[INET6_ADDRSTRLEN + 1];
    char dest[INET6_ADDRSTRLEN + 1];
    // Convert the IP addresses from binary to string format.
    inet_ntop(AF_INET, &s->udp.saddr.ip4, source, sizeof(source));
    inet_ntop(AF_INET, &s->udp.daddr.ip4, dest, sizeof(dest));


    // Calculate the timeout for the session.
    int timeout = get_udp_timeout(&s->udp, sessions, maxsessions);
    // If the session is active and has exceeded its timeout, log and update its state to finishing.
    if (s->udp.state == UDP_ACTIVE && s->udp.time + timeout < now) {
        log_android(ANDROID_LOG_WARN, "UDP idle %d/%d sec state %d from %s/%u to %s/%u",
                    now - s->udp.time, timeout, s->udp.state,
                    source, ntohs(s->udp.source), dest, ntohs(s->udp.dest));
        s->udp.state = UDP_FINISHING;
    }
    // If the session is in the finishing state, close its socket and update its state to closed.
    if (s->udp.state == UDP_FINISHING) {
        log_android(ANDROID_LOG_INFO, "UDP close from %s/%u to %s/%u socket %d",
                    source, ntohs(s->udp.source), dest, ntohs(s->udp.dest), s->socket);

        if (close(s->socket))
            log_android(ANDROID_LOG_ERROR, "UDP close %d error %d: %s",
                        s->socket, errno, strerror(errno));
        s->socket = -1;

        s->udp.time = time(NULL);
        s->udp.state = UDP_CLOSED;
    }
    // If the session is closed and there's data sent or received, account for the data usage.
    if (s->udp.state == UDP_CLOSED && (s->udp.sent || s->udp.received)) {
        account_usage(args, s->udp.version, IPPROTO_UDP,
                      dest, ntohs(s->udp.dest), s->udp.uid, s->udp.sent, s->udp.received);
        s->udp.sent = 0;
        s->udp.received = 0;
    }

    // Remove sessions that are lingering for too long.
    if ((s->udp.state == UDP_CLOSED || s->udp.state == UDP_BLOCKED) &&
        s->udp.time + UDP_KEEP_TIMEOUT < now)
        return 1;

    return 0;
}

// Function to check the state of the UDP socket and handle any events.
void check_udp_socket(const struct arguments *args, const struct epoll_event *ev) {
    // Extract the session from the epoll event.
    struct ng_session *s = (struct ng_session *) ev->data.ptr;

    // If there's an error on the socket, handle it.
    if (ev->events & EPOLLERR) {
        s->udp.time = time(NULL);
        // Fetch the socket error.
        int serr = 0;
        socklen_t optlen = sizeof(int);
        int err = getsockopt(s->socket, SOL_SOCKET, SO_ERROR, &serr, &optlen);
        if (err < 0)
            log_android(ANDROID_LOG_ERROR, "UDP getsockopt error %d: %s",
                        errno, strerror(errno));
        else if (serr)
            log_android(ANDROID_LOG_ERROR, "UDP SO_ERROR %d: %s", serr, strerror(serr));
        // Set the session state to finishing due to the error.
        s->udp.state = UDP_FINISHING;
    } else {
        // If there's data available to read on the socket, handle it.
        if (ev->events & EPOLLIN) {
            s->udp.time = time(NULL);
            // Allocate a buffer for reading data.
            uint8_t *buffer = malloc(s->udp.mss);
            ssize_t bytes = recv(s->socket, buffer, s->udp.mss, 0);
            if (bytes < 0) {
                // Handle socket read errors.
                log_android(ANDROID_LOG_WARN, "UDP recv error %d: %s",
                            errno, strerror(errno));
                // If the error is not due to an interrupted call or try again, set the session to finishing.
                if (errno != EINTR && errno != EAGAIN)
                    s->udp.state = UDP_FINISHING;
            } else if (bytes == 0) {
                // Handle end of file on the socket.
                log_android(ANDROID_LOG_WARN, "UDP recv eof");
                s->udp.state = UDP_FINISHING;

            } else {
                // Process the received data.
                char dest[INET6_ADDRSTRLEN + 1];
                inet_ntop(AF_INET, &s->udp.daddr.ip4, dest, sizeof(dest));
                log_android(ANDROID_LOG_INFO, "UDP recv bytes %d from %s/%u for tun",
                            bytes, dest, ntohs(s->udp.dest));
                // Update the total bytes received for the session.
                s->udp.received += bytes;

                // If the data is a DNS response, parse it.
                if (ntohs(s->udp.dest) == 53)
                    parse_dns_response(args, &s->udp, buffer, (size_t *) &bytes);

                // Forward the data to the TUN interface.
                if (write_udp(args, &s->udp, buffer, (size_t) bytes) < 0)
                    s->udp.state = UDP_FINISHING;
                else {
                    // If the data is a DNS query, set the session to finishing to prevent too many open files.
                    if (ntohs(s->udp.dest) == 53)
                        s->udp.state = UDP_FINISHING;
                }
            }
            // Free the allocated buffer.
            free(buffer);
        }
    }
}
// Function to check if there's an existing UDP session for the given packet.
int has_udp_session(const struct arguments *args, const uint8_t *pkt, const uint8_t *payload) {
    // Extract the version (IPv4 or IPv6) from the packet and get the UDP header from the payload.
    const uint8_t version = (*pkt) >> 4;
    const struct iphdr *ip4 = (struct iphdr *) pkt;
    const struct ip6_hdr *ip6 = (struct ip6_hdr *) pkt;
    const struct udphdr *udphdr = (struct udphdr *) payload;
    // If the destination port is 53 (DNS) and DNS forwarding is disabled, return true.
    if (ntohs(udphdr->dest) == 53 && !args->fwd53)
        return 1;

    // Search for a matching session in the list.
    struct ng_session *cur = args->ctx->ng_session;
    while (cur != NULL &&
           !(cur->protocol == IPPROTO_UDP &&
             cur->udp.version == version &&
             cur->udp.source == udphdr->source && cur->udp.dest == udphdr->dest &&
             (version == 4 ? cur->udp.saddr.ip4 == ip4->saddr &&
                             cur->udp.daddr.ip4 == ip4->daddr
                           : memcmp(&cur->udp.saddr.ip6, &ip6->ip6_src, 16) == 0 &&
                             memcmp(&cur->udp.daddr.ip6, &ip6->ip6_dst, 16) == 0)))
        cur = cur->next;
    // Return true if a matching session is found, false otherwise.
    return (cur != NULL);
}
// Function to block a given UDP session based on its packet details.
void block_udp(const struct arguments *args,
               const uint8_t *pkt, size_t length,
               const uint8_t *payload,
               int uid) {
    // Extract the version (IPv4 or IPv6) from the packet and get the UDP header from the payload.
    const uint8_t version = (*pkt) >> 4;
    const struct iphdr *ip4 = (struct iphdr *) pkt;
    const struct ip6_hdr *ip6 = (struct ip6_hdr *) pkt;
    const struct udphdr *udphdr = (struct udphdr *) payload;
    // Buffers to store the source and destination IP addresses as strings.
    char source[INET6_ADDRSTRLEN + 1];
    char dest[INET6_ADDRSTRLEN + 1];
    // Convert the IP addresses from binary to string format.
    inet_ntop(AF_INET, &ip4->saddr, source, sizeof(source));
    inet_ntop(AF_INET, &ip4->daddr, dest, sizeof(dest));
    // Log the details of the blocked session.
    log_android(ANDROID_LOG_INFO, "UDP blocked session from %s/%u to %s/%u",
                source, ntohs(udphdr->source), dest, ntohs(udphdr->dest));

    // Allocate memory for a new session and set its details.
    struct ng_session *s = malloc(sizeof(struct ng_session));
    s->protocol = IPPROTO_UDP;
    s->udp.time = time(NULL);
    s->udp.uid = uid;
    s->udp.version = version;
    s->udp.saddr.ip4 = (__be32) ip4->saddr;
    s->udp.daddr.ip4 = (__be32) ip4->daddr;
    s->udp.source = udphdr->source;
    s->udp.dest = udphdr->dest;
    s->udp.state = UDP_BLOCKED;
    s->socket = -1;
    // Add the new session to the beginning of the session list.
    s->next = args->ctx->ng_session;
    args->ctx->ng_session = s;
}

// Function to handle and process UDP packets
jboolean handle_udp(const struct arguments *args,
                    const uint8_t *pkt, size_t length,
                    const uint8_t *payload,
                    int uid, struct allowed *redirect,
                    const int epoll_fd) {
    // Extract the IP version from the packet header
    const uint8_t version = (*pkt) >> 4;
    // Cast the packet to IPv4 header
    const struct iphdr *ip4 = (struct iphdr *) pkt;
    // Cast the packet to IPv6 header
    const struct ip6_hdr *ip6 = (struct ip6_hdr *) pkt;
    // Cast the payload to UDP header to extract details
    const struct udphdr *udphdr = (struct udphdr *) payload;
    // Calculate the start of the actual data after the UDP header
    const uint8_t *data = payload + sizeof(struct udphdr);
    // Calculate the length of the actual data
    const size_t datalen = length - (data - pkt);

    // Search for an existing session that matches the current packet details
    struct ng_session *cur = args->ctx->ng_session;
    while (cur != NULL &&
           !(cur->protocol == IPPROTO_UDP &&
             cur->udp.version == version &&
             cur->udp.source == udphdr->source && cur->udp.dest == udphdr->dest &&
             (version == 4 ? cur->udp.saddr.ip4 == ip4->saddr &&
                             cur->udp.daddr.ip4 == ip4->daddr
                           : memcmp(&cur->udp.saddr.ip6, &ip6->ip6_src, 16) == 0 &&
                             memcmp(&cur->udp.daddr.ip6, &ip6->ip6_dst, 16) == 0)))
        cur = cur->next;

    // Convert the source and destination addresses to human-readable strings
    char source[INET6_ADDRSTRLEN + 1];
    char dest[INET6_ADDRSTRLEN + 1];
    inet_ntop(AF_INET, &ip4->saddr, source, sizeof(source));
    inet_ntop(AF_INET, &ip4->daddr, dest, sizeof(dest));

    // If the session exists and is not in an active state, log and ignore it
    if (cur != NULL && cur->udp.state != UDP_ACTIVE) {
        log_android(ANDROID_LOG_INFO, "UDP ignore session from %s/%u to %s/%u state %d",
                    source, ntohs(udphdr->source), dest, ntohs(udphdr->dest), cur->udp.state);
        return 0;
    }

    // If no matching session was found, create a new one
    if (cur == NULL) {
        log_android(ANDROID_LOG_INFO, "UDP new session from %s/%u to %s/%u",
                    source, ntohs(udphdr->source), dest, ntohs(udphdr->dest));

        // Allocate memory for the new session
        struct ng_session *s = malloc(sizeof(struct ng_session));
        s->protocol = IPPROTO_UDP;
        // Initialize session details
        s->udp.time = time(NULL);
        s->udp.uid = uid;
        s->udp.version = version;
        // Determine version for redirection (if applicable)
        int rversion;
        if (redirect == NULL)
            rversion = s->udp.version;
        else
            rversion = (strstr(redirect->raddr, ":") == NULL ? 4 : 6);
        // Set the maximum segment size based on the IP version
        s->udp.mss = (uint16_t) (rversion == 4 ? UDP4_MAXMSG : UDP6_MAXMSG);
        // Initialize byte counters
        s->udp.sent = 0;
        s->udp.received = 0;
        // Store the source and destination addresses in the session
        s->udp.saddr.ip4 = (__be32) ip4->saddr;
        s->udp.daddr.ip4 = (__be32) ip4->daddr;

        // Store source and destination ports in the session
        s->udp.source = udphdr->source;
        s->udp.dest = udphdr->dest;
        // Set session state to active
        s->udp.state = UDP_ACTIVE;
        s->next = NULL;

        // Open a new UDP socket for this session
        s->socket = open_udp_socket(args, &s->udp, redirect);
        if (s->socket < 0) {
            free(s);
            return 0;
        }
        // Open a new UDP socket for this session
        log_android(ANDROID_LOG_DEBUG, "UDP socket %d", s->socket);

        // Add the socket to epoll for monitoring events
        memset(&s->ev, 0, sizeof(struct epoll_event));
        s->ev.events = EPOLLIN | EPOLLERR;
        s->ev.data.ptr = s;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, s->socket, &s->ev))
            log_android(ANDROID_LOG_ERROR, "epoll add udp error %d: %s", errno, strerror(errno));
        // Link the new session to the list of sessions
        s->next = args->ctx->ng_session;
        args->ctx->ng_session = s;
        cur = s;
    }

    // Check if the packet is a DNS query (port 53)
    if (ntohs(udphdr->dest) == 53) {
        char qname[DNS_QNAME_MAX + 1];
        uint16_t qtype;
        uint16_t qclass;
        // Extract DNS query details
        if (get_dns_query(args, &cur->udp, data, datalen, &qtype, &qclass, qname) >= 0) {
            log_android(ANDROID_LOG_DEBUG,
                        "DNS query qtype %d qclass %d name %s",
                        qtype, qclass, qname);

            if (0)
                if (check_domain(args, &cur->udp, data, datalen, qclass, qtype, qname)) {
                    // Log the DNS query name
                    char name[DNS_QNAME_MAX + 40 + 1];
                    sprintf(name, "qtype %d qname %s", qtype, qname);
                    jobject objPacket = create_packet(
                            args, version, IPPROTO_UDP, "",
                            source, ntohs(cur->udp.source), dest, ntohs(cur->udp.dest),
                            name, 0, 0);
                    log_packet(args, objPacket);

                    // If the domain check fails, set the session to finishing state and exit
                    cur->udp.state = UDP_FINISHING;
                    return 0;
                }
        }
    }

    // Check if the packet is a DHCP request or response (ports 67/68)
    if (ntohs(udphdr->source) == 68 || ntohs(udphdr->dest) == 67) {
        if (check_dhcp(args, &cur->udp, data, datalen) >= 0)
            return 1;
    }
    // Log the details of the packet
    log_android(ANDROID_LOG_INFO, "UDP forward from tun %s/%u to %s/%u data %d",
                source, ntohs(udphdr->source), dest, ntohs(udphdr->dest), datalen);

    // Update the last seen timestamp for the session
    cur->udp.time = time(NULL);

    // Determine the version for redirect (if any) and prepare the target address structure
    int rversion;
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
    if (redirect == NULL) {
        rversion = cur->udp.version;
        if (cur->udp.version == 4) {
            addr4.sin_family = AF_INET;
            addr4.sin_addr.s_addr = (__be32) cur->udp.daddr.ip4;
            addr4.sin_port = cur->udp.dest;
        } else {
            addr6.sin6_family = AF_INET6;
            memcpy(&addr6.sin6_addr, &cur->udp.daddr.ip6, 16);
            addr6.sin6_port = cur->udp.dest;
        }
    } else {
        rversion = (strstr(redirect->raddr, ":") == NULL ? 4 : 6);
        log_android(ANDROID_LOG_WARN, "UDP%d redirect to %s/%u",
                    rversion, redirect->raddr, redirect->rport);

        // Populate the target address based on redirect details
        if (rversion == 4) {
            addr4.sin_family = AF_INET;
            inet_pton(AF_INET, redirect->raddr, &addr4.sin_addr);
            addr4.sin_port = htons(redirect->rport);
        } else {
            addr6.sin6_family = AF_INET6;
            inet_pton(AF_INET6, redirect->raddr, &addr6.sin6_addr);
            addr6.sin6_port = htons(redirect->rport);
        }
    }
    // Send the packet data to the target address
    if (sendto(cur->socket, data, (socklen_t) datalen, MSG_NOSIGNAL,
               (rversion == 4 ? (const struct sockaddr *) &addr4
                              : (const struct sockaddr *) &addr6),
               (socklen_t) (rversion == 4 ? sizeof(addr4) : sizeof(addr6))) != datalen) {
        // Log an error if the send operation fails
        log_android(ANDROID_LOG_ERROR, "UDP sendto error %d: %s", errno, strerror(errno));
        // If the error is not temporary, set the session state to finishing
        if (errno != EINTR && errno != EAGAIN) {
            cur->udp.state = UDP_FINISHING;
            return 0;
        }
    } else
        cur->udp.sent += datalen;// Update byte counter for sent data
    return 1;
}

// This function opens a UDP socket based on the session and any redirection rules.
int open_udp_socket(const struct arguments *args,
                    const struct udp_session *cur, const struct allowed *redirect) {
    int sock;
    int version;
    // Determine the IP version for the socket (either IPv4 or IPv6) based on the redirection rule.
    if (redirect == NULL)
        version = cur->version;
    else
        version = (strstr(redirect->raddr, ":") == NULL ? 4 : 6);

    // Create a UDP socket
    sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        // Log if there's an error creating the socket.
        log_android(ANDROID_LOG_ERROR, "UDP socket error %d: %s", errno, strerror(errno));
        return -1;
    }

    // Protect the socket from being routed back into the VPN.
    if (protect_socket(args, sock) < 0)
        return -1;

    // Check if the destination address is a broadcast or multicast address.
    if (cur->version == 4) {
        uint32_t broadcast4 = INADDR_BROADCAST;
        if (memcmp(&cur->daddr.ip4, &broadcast4, sizeof(broadcast4)) == 0) {
            log_android(ANDROID_LOG_WARN, "UDP4 broadcast");
            int on = 1;
            // Allow broadcasting on the socket.
            if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)))
                log_android(ANDROID_LOG_ERROR, "UDP setsockopt SO_BROADCAST error %d: %s",
                            errno, strerror(errno));
        }
    } else {

    }
    // Return the created socket.
    return sock;
}

// This function sends UDP data to the TUN interface.
ssize_t write_udp(const struct arguments *args, const struct udp_session *cur,
                  uint8_t *data, size_t datalen) {
    size_t len;
    u_int8_t *buffer;
    struct udphdr *udp;
    uint16_t csum;

    // Buffer to store source and destination IP addresses in string format.
    char source[INET6_ADDRSTRLEN + 1];
    char dest[INET6_ADDRSTRLEN + 1];

    // Construct an IP packet with an embedded UDP packet.
    if (cur->version == 4) {
        // Calculate the total length for the IPv4 packet.
        len = sizeof(struct iphdr) + sizeof(struct udphdr) + datalen;
        // Allocate memory for the packet.
        buffer = malloc(len);
        // Cast the beginning of the buffer to an IPv4 header.
        struct iphdr *ip4 = (struct iphdr *) buffer;
        udp = (struct udphdr *) (buffer + sizeof(struct iphdr));
        // If there's data, copy it after the UDP header.
        if (datalen)
            memcpy(buffer + sizeof(struct iphdr) + sizeof(struct udphdr), data, datalen);

        // Set up the IPv4 header.
        memset(ip4, 0, sizeof(struct iphdr));
        ip4->version = 4;
        ip4->ihl = sizeof(struct iphdr) >> 2;
        ip4->tot_len = htons(len);
        ip4->ttl = IPDEFTTL;
        ip4->protocol = IPPROTO_UDP;
        ip4->saddr = cur->daddr.ip4;
        ip4->daddr = cur->saddr.ip4;

        // Compute the checksum for the IPv4 header.
        ip4->check = ~calc_checksum(0, (uint8_t *) ip4, sizeof(struct iphdr));

        // Prepare the structure for UDP checksum computation for IPv4.
        struct ippseudo pseudo;
        memset(&pseudo, 0, sizeof(struct ippseudo));
        pseudo.ippseudo_src.s_addr = (__be32) ip4->saddr;
        pseudo.ippseudo_dst.s_addr = (__be32) ip4->daddr;
        pseudo.ippseudo_p = ip4->protocol;
        pseudo.ippseudo_len = htons(sizeof(struct udphdr) + datalen);
        // Compute the initial part of the checksum using the pseudo-header.
        csum = calc_checksum(0, (uint8_t *) &pseudo, sizeof(struct ippseudo));
    } else {

    }

    // Set up the UDP header.
    memset(udp, 0, sizeof(struct udphdr));
    udp->source = cur->dest;
    udp->dest = cur->source;
    udp->len = htons(sizeof(struct udphdr) + datalen);

    // Compute the final checksum using UDP header and data.
    csum = calc_checksum(csum, (uint8_t *) udp, sizeof(struct udphdr));
    csum = calc_checksum(csum, data, datalen);
    udp->check = ~csum;
    // Convert source and destination IP addresses to string for logging.
    inet_ntop(AF_INET, (const void *) &cur->saddr.ip4, source, sizeof(source));
    inet_ntop(AF_INET, (const void *) &cur->daddr.ip4, dest, sizeof(dest));

    // Log the details of the packet being sent to TUN.
    log_android(ANDROID_LOG_DEBUG,
                "UDP sending to tun %d from %s/%u to %s/%u data %u",
                args->tun, dest, ntohs(cur->dest), source, ntohs(cur->source), len);
    // Send the constructed packet to the TUN interface.
    ssize_t res = write(args->tun, buffer, len);

    // Free the allocated buffer.
    free(buffer);
    // Log if the number of bytes written doesn't match the expected length.
    if (res != len) {
        log_android(ANDROID_LOG_ERROR, "write %d/%d", res, len);
        return -1;
    }
    return res;
}
