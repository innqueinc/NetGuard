# VPN Application Flow Overview

This document provides a comprehensive overview of the VPN application's flow, detailing how
different components interact with each other, from the service initialization in Android to the
handling of network packets in native C code.

## Table of Contents

1. [Service Initialization](#service-initialization)
2. [Starting the VPN](#starting-the-vpn)
3. [Native Code Execution](#native-code-execution)
4. [Handling Network Events](#handling-network-events)
5. [Processing Packets](#processing-packets)
6. [Protocol-Specific Handling](#protocol-specific-handling)
7. [Session Management](#session-management)
8. [Utility Functions](#utility-functions)

## Service Initialization

When `ServiceSinkhole` is created:

- The `jni_init` function is called to initialize JNI-related variables, such as the app context and
  signal pipe.
- Any Android-specific callbacks, listeners, or resources might also be initialized here.

## Starting the VPN

Upon triggering `ServiceSinkhole.onStartCommand`:

- Depending on the intent action, different tasks might be executed (e.g., stopping the service,
  restarting it).
- The VPN is set up by creating a `Builder`, defining its properties, and then calling `establish`
  to obtain a file descriptor for the VPN interface.

## Native Code Execution

### jni_start:

- Signals the native code to start the VPN processing.
- Initializes global or static variables related to the VPN.

### jni_run:

- Represents the main loop for VPN packet handling.
- Uses the `epoll` system call to wait for events on monitored file descriptors, primarily the `tun`
  descriptor.

## Handling Network Events

### handle_events (`session.c`):

- Manages various file descriptors, including the `tun`.
- Calls the corresponding handler for a descriptor when an event occurs. For `tun`, it's `check_tun`
  .

## Processing Packets

### check_tun (`ip.c`):

- Checks for errors on the `tun`.
- If a packet is received, it's read into a buffer and processed using `handle_ip`.

### handle_ip (`ip.c`):

- Determines the IP version of the packet.
- Retrieves key information from the header.
- Processes the packet based on its protocol (TCP, UDP, ICMP, etc.).
- Checks if the packet's source address is allowed, possibly dropping it or taking other actions.

## Protocol-Specific Handling

- `tcp.c`: Contains functions to handle TCP packets, manage connections, and handle state
  transitions.
- `udp.c`: Manages functions related to UDP packet handling.
- `icmp.c` and others: Handle their respective protocols.

## Session Management

### `session.c`:

- Manages VPN sessions, tracking active connections.
- Ensures old/inactive sessions are cleaned up.
- Provides utilities for session management tasks.

## Utility Functions

### `util.c`:

- Contains utility functions used across the VPN codebase.
- Includes common tasks like checksum calculations and logging.

---

This README is a high-level guide to the VPN application's flow. For deeper insights or specifics
about any function or interaction, please refer to the respective source code files or
documentation.