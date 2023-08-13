#include "netguard.h"
/*
 * This code is for checking and handling DHCP packets.
 * DHCP (Dynamic Host Configuration Protocol) is a network protocol used to assign IP addresses and other network configuration to devices.
 * If a DHCP discover or request packet is detected, the function creates a corresponding DHCP offer or acknowledgment response.
 * */
// Check if the incoming data is a DHCP packet and handle accordingly.
int check_dhcp(const struct arguments *args, const struct udp_session *u,
               const uint8_t *data, const size_t datalen) {

    // This is untested
    // Android routing of DHCP is erroneous
    // Warning note: The following DHCP logic has not been tested.
    log_android(ANDROID_LOG_WARN, "DHCP check");
    // Ensure that the data length is at least the size of a DHCP packet.
    if (datalen < sizeof(struct dhcp_packet)) {
        log_android(ANDROID_LOG_WARN, "DHCP packet size %d", datalen);
        return -1;
    }
    // Cast the data to a DHCP packet structure for easier access to its fields.
    const struct dhcp_packet *request = (struct dhcp_packet *) data;
    // Check if the option format of the DHCP request is valid.
    if (ntohl(request->option_format) != DHCP_OPTION_MAGIC_NUMBER) {
        log_android(ANDROID_LOG_WARN, "DHCP invalid magic %x", request->option_format);
        return -1;
    }
    // Ensure the hardware type and length are correct (Ethernet and 6 bytes for MAC address).
    if (request->htype != 1 || request->hlen != 6) {
        log_android(ANDROID_LOG_WARN, "DHCP unknown hardware htype %d hlen %d",
                    request->htype, request->hlen);
        return -1;
    }
    // Log the opcode from the DHCP request.
    log_android(ANDROID_LOG_WARN, "DHCP opcode", request->opcode);

    // Discover: source 0.0.0.0:68 destination 255.255.255.255:67
    // Offer: source 10.1.10.1:67 destination 255.255.255.255:68
    // Request: source 0.0.0.0:68 destination 255.255.255.255:67
    // Ack: source: 10.1.10.1 destination: 255.255.255.255
    // Check if the DHCP packet is a discover or request.
    if (request->opcode == 1) { // Discover/request
        struct dhcp_packet *response = calloc(500, 1);

        // Hack: Set the source address for the response to "10.1.10.1".
        inet_pton(AF_INET, "10.1.10.1", (void *) &u->saddr);

        /*
        Discover:
            DHCP option 53: DHCP Discover
            DHCP option 50: 192.168.1.100 requested
            DHCP option 55: Parameter Request List:
            Request Subnet Mask (1), Router (3), Domain Name (15), Domain Name Server (6)

        Request
            DHCP option 53: DHCP Request
            DHCP option 50: 192.168.1.100 requested
            DHCP option 54: 192.168.1.1 DHCP server.
        */
        // Create a DHCP response based on the request.
        memcpy(response, request, sizeof(struct dhcp_packet));
        response->opcode = (uint8_t) (request->siaddr == 0 ? 2 /* Offer */ : /* Ack */ 4);
        // Reset some fields in the response.
        response->secs = 0;
        response->flags = 0;
        memset(&response->ciaddr, 0, sizeof(response->ciaddr));
        // Assign a client IP address and server IP address in the response.
        inet_pton(AF_INET, "10.1.10.2", &response->yiaddr);
        inet_pton(AF_INET, "10.1.10.1", &response->siaddr);
        // Reset the gateway address in the response.
        memset(&response->giaddr, 0, sizeof(response->giaddr));

        // https://tools.ietf.org/html/rfc2132
        // Start adding DHCP options to the response.
        uint8_t *options = (uint8_t *) (response + sizeof(struct dhcp_packet));
        // Initialize option index.
        int idx = 0;
        // Add the DHCP message type option (either "Offer" or "Ack").
        *(options + idx++) = 53; // Message type
        *(options + idx++) = 1;
        *(options + idx++) = (uint8_t) (request->siaddr == 0 ? 2 : 5);
        /*
             1     DHCPDISCOVER
             2     DHCPOFFER
             3     DHCPREQUEST
             4     DHCPDECLINE
             5     DHCPACK
             6     DHCPNAK
             7     DHCPRELEASE
             8     DHCPINFORM
         */
        // Add the subnet mask option.
        *(options + idx++) = 1; // subnet mask
        *(options + idx++) = 4; // IP4 length
        inet_pton(AF_INET, "255.255.255.0", options + idx);
        idx += 4;
        // Add the gateway (router) option.
        *(options + idx++) = 3; // gateway
        *(options + idx++) = 4; // IP4 length
        inet_pton(AF_INET, "10.1.10.1", options + idx);
        idx += 4;
        // Add the IP address lease time option.
        *(options + idx++) = 51; // lease time
        *(options + idx++) = 4; // quad
        *((uint32_t *) (options + idx)) = 3600;
        idx += 4;
        // Add the DHCP server identifier option.
        *(options + idx++) = 54; // DHCP
        *(options + idx++) = 4; // IP4 length
        inet_pton(AF_INET, "10.1.10.1", options + idx);
        idx += 4;
        // Add the DNS server option.
        *(options + idx++) = 6; // DNS
        *(options + idx++) = 4; // IP4 length
        inet_pton(AF_INET, "8.8.8.8", options + idx);
        idx += 4;

        // End the options section.
        *(options + idx++) = 255; // End

        /*
            DHCP option 53: DHCP Offer
            DHCP option 1: 255.255.255.0 subnet mask
            DHCP option 3: 192.168.1.1 router
            DHCP option 51: 86400s (1 day) IP address lease time
            DHCP option 54: 192.168.1.1 DHCP server
            DHCP option 6: DNS servers 9.7.10.15
         */
        // Send the DHCP response.
        write_udp(args, u, (uint8_t *) response, 500);
        // Clean up and free the allocated memory for the response.
        free(response);
    }

    return 0;
}
