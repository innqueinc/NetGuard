#include "netguard.h"

extern int loglevel;

// Calculate the checksum for a given buffer.
uint16_t calc_checksum(uint16_t start, const uint8_t *buffer, size_t length) {
    // Initialize a 32-bit sum with the provided start value.
    register uint32_t sum = start;
    // Create a pointer to the buffer, treating it as an array of 16-bit values.
    register uint16_t *buf = (uint16_t *) buffer;
    // Initialize a variable to keep track of the remaining length of the buffer.
    register size_t len = length;
    // Continue processing as long as there are at least 2 bytes left in the buffer.
    while (len > 1) {
        sum += *buf++; // Add the current 16-bit value to the sum and move to the next.
        len -= 2; // Decrement the remaining length by 2 bytes.
    }
    // If there's one byte left in the buffer, add it to the sum.
    if (len > 0)
        sum += *((uint8_t *) buf);
    // Fold the sum to get a 16-bit result.
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    // Return the resulting checksum.
    return (uint16_t) sum;
}
// Compare two 32-bit unsigned integers using the rules from RFC 1982.
int compare_u32(uint32_t s1, uint32_t s2) {
    // https://tools.ietf.org/html/rfc1982
    // If both numbers are equal, return 0.
    if (s1 == s2)
        return 0;
    // Convert the unsigned 32-bit numbers to signed integers for comparison.
    int i1 = s1;
    int i2 = s2;
    // Compare the two numbers based on the rules from RFC 1982.
    if ((i1 < i2 && i2 - i1 < 0x7FFFFFFF) ||
        (i1 > i2 && i1 - i2 > 0x7FFFFFFF))
        return -1;
    else
        return 1;
}
// Get the SDK version from the Android operating system.
int sdk_int(JNIEnv *env) {
    // Find the VERSION class from the Android OS Build.
    jclass clsVersion = jniFindClass(env, "android/os/Build$VERSION");
    // Get the field ID for the static SDK_INT field.
    jfieldID fid = (*env)->GetStaticFieldID(env, clsVersion, "SDK_INT", "I");
    // Return the value of the SDK_INT field.
    return (*env)->GetStaticIntField(env, clsVersion, fid);
}
// Log messages to the Android logging system.
void log_android(int prio, const char *fmt, ...) {
    // Only proceed if the priority of the message is greater than or equal to the log level.
    if (prio >= loglevel) {
        char line[1024];
        // Format the log message.
        va_list argptr;
        va_start(argptr, fmt);
        vsprintf(line, fmt, argptr);
        // Print the message to the Android log.
        __android_log_print(prio, TAG, "%s", line);
        va_end(argptr);
    }
}
// Convert a hexadecimal character to its numerical value.
uint8_t char2nible(const char c) {
    if (c >= '0' && c <= '9') return (uint8_t) (c - '0');
    if (c >= 'a' && c <= 'f') return (uint8_t) ((c - 'a') + 10);
    if (c >= 'A' && c <= 'F') return (uint8_t) ((c - 'A') + 10);
    return 255;  // Invalid character.
}
// Convert a string of hexadecimal characters to an array of bytes.
void hex2bytes(const char *hex, uint8_t *buffer) {
    size_t len = strlen(hex);
    for (int i = 0; i < len; i += 2)
        buffer[i / 2] = (char2nible(hex[i]) << 4) | char2nible(hex[i + 1]);
}
// Remove whitespace from the beginning and end of a string.
char *trim(char *str) {
    while (isspace(*str))
        str++;
    if (*str == 0)
        return str;

    char *end = str + strlen(str) - 1;
    while (end > str && isspace(*end))
        end--;
    *(end + 1) = 0;
    return str;
}
// Convert a TCP state value to its string representation.
const char *strstate(const int state) {
    switch (state) {
        case TCP_ESTABLISHED:
            return "ESTABLISHED";
        case TCP_SYN_SENT:
            return "SYN_SENT";
        case TCP_SYN_RECV:
            return "SYN_RECV";
        case TCP_FIN_WAIT1:
            return "FIN_WAIT1";
        case TCP_FIN_WAIT2:
            return "FIN_WAIT2";
        case TCP_TIME_WAIT:
            return "TIME_WAIT";
        case TCP_CLOSE:
            return "CLOSE";
        case TCP_CLOSE_WAIT:
            return "CLOSE_WAIT";
        case TCP_LAST_ACK:
            return "LAST_ACK";
        case TCP_LISTEN:
            return "LISTEN";
        case TCP_CLOSING:
            return "CLOSING";
        default:
            return "UNKNOWN";
    }
}
// Convert an array of bytes to a space-separated string of hexadecimal values.
char *hex(const u_int8_t *data, const size_t len) {
    char hex_str[] = "0123456789ABCDEF";

    char *hexout;
    hexout = (char *) malloc(len * 3 + 1);  // Allocate memory for the resulting string.

    for (size_t i = 0; i < len; i++) {
        hexout[i * 3 + 0] = hex_str[(data[i] >> 4) & 0x0F];
        hexout[i * 3 + 1] = hex_str[(data[i]) & 0x0F];
        hexout[i * 3 + 2] = ' ';
    }
    hexout[len * 3] = 0;

    return hexout; // Return the hexadecimal string.
}
// Get the local port number associated with a socket.
int32_t get_local_port(const int sock) {
    struct sockaddr_in sin;
    socklen_t len = sizeof(sin);
    if (getsockname(sock, (struct sockaddr *) &sin, &len) < 0) {
        log_android(ANDROID_LOG_ERROR, "getsockname error %d: %s", errno, strerror(errno));
        return -1;
    } else
        return ntohs(sin.sin_port); // Return the port number.
}
// Check if a certain event is set for a file descriptor using poll.
int is_event(int fd, short event) {
    struct pollfd p;
    p.fd = fd;
    p.events = event;
    p.revents = 0;
    int r = poll(&p, 1, 0);
    if (r < 0) {
        log_android(ANDROID_LOG_ERROR, "poll readable error %d: %s", errno, strerror(errno));
        return 0;
    } else if (r == 0)
        return 0;
    else
        return (p.revents & event); // Return whether the desired event was set.
}
// Check if a file descriptor is ready for reading.
int is_readable(int fd) {
    return is_event(fd, POLLIN);
}
// Check if a file descriptor is ready for writing.
int is_writable(int fd) {
    return is_event(fd, POLLOUT);
}
// Get the current time in milliseconds.
long long get_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000LL + ts.tv_nsec / 1e6; // Convert to milliseconds and return.
}
