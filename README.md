libre README
============


libre is a Generic library for real-time communications with async IO support.

- Copyright (C) 2010 - 2020 Creytiv.com
- Copyright (C) 2020 - 2022 Baresip Foundation (https://github.com/baresip)

![Build](https://github.com/baresip/re/workflows/Build/badge.svg)
![ccheck](https://github.com/baresip/re/workflows/ccheck/badge.svg)
![OpenSSL no-deprecated and LibreSSL](https://github.com/baresip/re/workflows/OpenSSL%20no-deprecated%20and%20LibreSSL/badge.svg)


## Features

* SIP Stack ([RFC 3261](https://tools.ietf.org/html/rfc3261))
* SDP
* RTP and RTCP
* SRTP and SRTCP (Secure RTP)
* DNS-Client
* STUN/TURN/ICE stack
* BFCP
* HTTP-stack with client/server
* Websockets
* Jitter-buffer
* Async I/O (poll, epoll, select, kqueue)
* UDP/TCP/TLS/DTLS transport
* JSON parser
* Real Time Messaging Protocol (RTMP)


## Building

libre is using GNU makefiles. Make and OpenSSL development headers must be
installed before building.


### Build with debug enabled

```
$ make
$ sudo make install
$ sudo ldconfig
```

On some distributions, /usr/local/lib may not be included in ld.so.conf. 
You can check with `grep "/usr/local/lib" /etc/ld.so.conf.d/*.conf` 
and add if necessary:

```
$ echo "/usr/local/lib" | sudo tee /etc/ld.so.conf.d/libc.conf
$ sudo ldconfig
```


### Build with release

```
$ make RELEASE=1
$ sudo make RELEASE=1 install
$ sudo ldconfig
```

### Build with clang compiler

```
$ make CC=clang
$ sudo make CC=clang install
$ sudo ldconfig
```


### Examples

Coding examples are available from the
[redemo](http://creytiv.com/pub/redemo-0.5.0.tar.gz) project


## License

The libre project is using the BSD license.


## Contributing

Patches can sent via Github
[Pull-Requests](https://github.com/baresip/re/pulls)


## Design goals

* Portable POSIX source code (ISO C99 and C11 standard)
* Robust, fast, low memory footprint
* RFC compliance
* IPv4 and IPv6 support


## Modules

| Name     | Status   | Description                                    |
|----------|----------|------------------------------------------------|
| aes      | stable   | AES (Advanced Encryption Standard)             |
| base64   | stable   | Base-64 encoding/decoding functions            |
| bfcp     | stable   | The Binary Floor Control Protocol (BFCP)       |
| conf     | stable   | Configuration file parser                      |
| crc32    | stable   | 32-bit CRC defined in ITU V.42                 |
| dbg      | stable   | Debug printing                                 |
| dns      | stable   | DNS resolving (NAPTR, SRV, A)                  |
| fmt      | stable   | Formatted printing and regular expression      |
| hash     | stable   | Hashmap table                                  |
| hmac     | stable   | HMAC: Keyed-Hashing for Message Authentication |
| http     | stable   | HTTP parser (RFC 2616)                         |
| httpauth | stable   | HTTP-based Authentication (RFC 2617)           |
| ice      | stable   | Interactive Connectivity Establishment (ICE)   |
| jbuf     | stable   | Jitter buffer                                  |
| json     | stable   | JavaScript Object Notation (JSON)              |
| list     | stable   | Sortable doubly-linked list handling           |
| lock     | stable   | Resource locking functions                     |
| main     | stable   | Main poll loop                                 |
| mbuf     | stable   | Linear memory buffers                          |
| md5      | stable   | The MD5 Message-Digest Algorithm (RFC 1321)    |
| mem      | stable   | Memory referencing                             |
| mod      | stable   | Run-time module loading                        |
| mqueue   | stable   | Thread-safe message queue                      |
| msg      | stable   | Generic message component library              |
| net      | stable   | Networking routines                            |
| odict    | stable   | Ordered Dictionary                             |
| rtmp     | stable   | Real Time Messaging Protocol                   |
| rtp      | stable   | Real-time Transport Protocol                   |
| sa       | stable   | Socket Address functions                       |
| sdp      | stable   | Session Description Protocol                   |
| sha      | stable   | Secure Hash Standard, NIST, FIPS PUB 180-1     |
| sip      | stable   | Core SIP library                               |
| sipevent | stable   | SIP Event framework                            |
| sipreg   | stable   | SIP register client                            |
| sipsess  | stable   | SIP Sessions                                   |
| srtp     | stable   | Secure Real-time Transport Protocol (SRTP)     |
| stun     | stable   | Session Traversal Utilities for NAT (STUN)     |
| sys      | stable   | System information                             |
| tcp      | stable   | TCP transport                                  |
| telev    | stable   | Telephony Events (RFC 4733)                    |
| thread   | testing  | C11 threads (with pthread and win32 emulation) |
| tls      | stable   | Transport Layer Security                       |
| tmr      | stable   | Timer handling                                 |
| turn     | stable   | Obtaining Relay Addresses from STUN (TURN)     |
| udp      | stable   | UDP transport                                  |
| uri      | stable   | Generic URI library                            |
| websock  | stable   | WebSocket Client and Server                    |
| trace    | testing  | Trace Helpers JSON traces (chrome://tracing)   |

legend:
* *stable* - code complete; stable code and stable API
* *testing* - code complete, but API might change
* *unstable* - code complete but not completely tested
* *development* - code is under development


## Features

* [RFC 1321](https://tools.ietf.org/html/rfc1321) - The MD5 Message-Digest Algorithm
* [RFC 1886](https://tools.ietf.org/html/rfc1886) - DNS Extensions to support IP version 6
* [RFC 2032](https://tools.ietf.org/html/rfc2032) - RTP Payload Format for H.261 Video Streams
* [RFC 2616](https://tools.ietf.org/html/rfc2616) - Hypertext Transfer Protocol -- HTTP/1.1
* [RFC 2617](https://tools.ietf.org/html/rfc2617) - HTTP Authentication: Basic and Digest Access Authentication
* [RFC 2782](https://tools.ietf.org/html/rfc2782) - A DNS RR for Specifying the Location of Services (DNS SRV)
* [RFC 2915](https://tools.ietf.org/html/rfc2915) - The Naming Authority Pointer (NAPTR) DNS Resource Record
* [RFC 3261](https://tools.ietf.org/html/rfc3261) - SIP: Session Initiation Protocol
* [RFC 3263](https://tools.ietf.org/html/rfc3263) - Locating SIP Servers
* [RFC 3264](https://tools.ietf.org/html/rfc3264) - An Offer/Answer Model with SDP
* [RFC 3265](https://tools.ietf.org/html/rfc3265) - SIP-Specific Event Notification
* [RFC 3327](https://tools.ietf.org/html/rfc3327) - SIP Extension Header Field for Registering Non-Adjacent Contacts
* [RFC 3428](https://tools.ietf.org/html/rfc3428) - SIP Extension for Instant Messaging
* [RFC 3489](https://tools.ietf.org/html/rfc3489) - STUN - Simple Traversal of UDP Through NATs
* [RFC 3515](https://tools.ietf.org/html/rfc3515) - The SIP Refer Method
* [RFC 3550](https://tools.ietf.org/html/rfc3550) - RTP: A Transport Protocol for Real-Time Applications
* [RFC 3551](https://tools.ietf.org/html/rfc3551) - RTP Profile for Audio and Video Conferences with Minimal Control
* [RFC 3555](https://tools.ietf.org/html/rfc3555) - MIME Type Registration of RTP Payload Formats
* [RFC 3556](https://tools.ietf.org/html/rfc3556) - SDP Bandwidth Modifiers for RTCP Bandwidth
* [RFC 3581](https://tools.ietf.org/html/rfc3581) - An Extension to SIP for Symmetric Response Routing
* [RFC 3605](https://tools.ietf.org/html/rfc3605) - RTCP attribute in SDP
* [RFC 3711](https://tools.ietf.org/html/rfc3711) - The Secure Real-time Transport Protocol (SRTP)
* [RFC 3969](https://tools.ietf.org/html/rfc3969) - The IANA URI Parameter Registry for SIP
* [RFC 3994](https://tools.ietf.org/html/rfc3994) - Indication of Message Composition for Instant Messaging
* [RFC 4346](https://tools.ietf.org/html/rfc4346) - The TLS Protocol Version 1.1
* [RFC 4566](https://tools.ietf.org/html/rfc4566) - SDP: Session Description Protocol
* [RFC 4582](https://tools.ietf.org/html/rfc4582) - The Binary Floor Control Protocol (BFCP)
* [RFC 4582bis](https://tools.ietf.org/html/draft-ietf-bfcpbis-rfc4582bis-08) - The Binary Floor Control Protocol (BFCP)
* [RFC 4585](https://tools.ietf.org/html/rfc4585) - Extended RTP Profile for RTCP-Based Feedback
* [RFC 4733](https://tools.ietf.org/html/rfc4733) - RTP Payload for DTMF Digits, Telephony Tones, and Teleph. Signals
* [RFC 4961](https://tools.ietf.org/html/rfc4961) - Symmetric RTP / RTP Control Protocol (RTCP)
* [RFC 5118](https://tools.ietf.org/html/rfc5118) - SIP Torture Test Messages for IPv6
* [RFC 5245](https://tools.ietf.org/html/rfc5245) - Interactive Connectivity Establishment (ICE)
* [RFC 5389](https://tools.ietf.org/html/rfc5389) - Session Traversal Utilities for NAT (STUN)
* [RFC 5626](https://tools.ietf.org/html/rfc5626) - Managing Client-Initiated Connections in SIP
* [RFC 5761](https://tools.ietf.org/html/rfc5761) - Multiplexing RTP Data and Control Packets on a Single Port
* [RFC 5766](https://tools.ietf.org/html/rfc5766) - Traversal Using Relays around NAT (TURN)
* [RFC 5768](https://tools.ietf.org/html/rfc5768) - Indicating Support for ICE in SIP
* [RFC 5769](https://tools.ietf.org/html/rfc5769) - Test vectors for STUN
* [RFC 5780](https://tools.ietf.org/html/rfc5780) - NAT Behaviour Discovery Using STUN
* [RFC 6026](https://tools.ietf.org/html/rfc6026) - Correct Transaction Handling for 2xx Resp. to SIP INVITE Requests
* [RFC 6156](https://tools.ietf.org/html/rfc6156) - TURN Extension for IPv6
* [RFC 6188](https://tools.ietf.org/html/rfc6188) - The Use of AES-192 and AES-256 in Secure RTP
* [RFC 6455](https://tools.ietf.org/html/rfc6455) - The WebSocket Protocol
* [RFC 7159](https://tools.ietf.org/html/rfc7159) - JavaScript Object Notation (JSON)
* [RFC 7350](https://tools.ietf.org/html/rfc7350) - DTLS as Transport for STUN
* [RFC 7714](https://tools.ietf.org/html/rfc7714) - AES-GCM Authenticated Encryption in SRTP


## Supported platforms

|  System | Support type | Supported versions | Notes |
|---|---|---|---|
| Linux | Tier 1 | glibc >= 2.17 (CentOS 7) | |
| macOS | Tier 1 | macOS >= 10.10 | |
| Windows | Tier 1 | >= Windows 8 | MinGW-w64 |
| Android | Tier 2 | | |
| iOS | Tier 2 | | |
| FreeBSD | Tier 2 | >= 11 | |
| OpenBSD | Tier 2 | >= 6.7 | |
| Linux | Tier 2 | uClibc | |
| Windows | Tier 3 | | e.g. VS 2015 |


### Support types

* **Tier 1**: Officially supported and tested with CI. Any contributed patch
  MUST NOT break such systems.

* **Tier 2**: Officially supported, but not necessarily tested with CI. These
  systems are maintained to the best of collaborators ability, without being
  a top priority.

* **Tier 3**: Community maintained. These systems may inadvertently break and the
  community and interested parties are expected to help with the maintenance.


### Supported versions of C Standard library

* Android bionic
* BSD libc
* GNU C Library (glibc)
* Windows C Run-Time Libraries (CRT)
* uClibc


### Supported compilers:

* gcc 4.9 or later
* MSVC 2019
* clang 3.x or later


### Supported versions of OpenSSL

* OpenSSL version 1.1.0
* OpenSSL version 1.1.1
* OpenSSL version 3.0.x
* LibreSSL version 3.x


## Coding guidelines

* Use enum for constants where appropriate
* Use const as much as possible (where appropriate)
* Use C99 data types (intN_t, uintN_t, bool)
* Hide data-types in .c files where possible (use struct foo)
* Avoid malloc/free, use mem_alloc/mem_deref instead
* CVS/svn/git tags are NOT allowed in the code!
* Avoid bit-fields in structs which are not portable
* Use dummy handlers for timing-critical callbacks
* return err, return alloced objects as pointer-pointers
* in allocating functions, first arg is always double pointer
* Use POSIX error-codes; EINVAL for invalid args, EBADMSG for
  parse errors and EPROTO for protocol errors


## Transport protocols


|         | TCP | UDP | TLS | DTLS|
|:--------|:---:|:---:|:---:|:---:|
| BFCP    | -   | yes | -   | -   |
| DNS     | yes | yes | -   | -   |
| HTTP    | yes | n/a | yes | n/a |
| ICE     | -   | yes | -   | -   |
| RTP     | -   | yes | -   | -   |
| RTCP    | -   | yes | -   | -   |
| RTMP    | yes | -   | yes | -   |
| SIP     | yes | yes | yes | -   |
| STUN    | yes | yes | yes | yes |
| TURN    | yes | yes | yes | yes |
| WEBSOCK | yes | n/a | yes | n/a |


## Related projects

* [librem](https://github.com/baresip/rem)
* [retest](https://github.com/baresip/retest)
* [baresip](https://github.com/baresip/baresip)


## References

https://github.com/creytiv/re
