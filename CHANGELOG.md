# libre Changelog

All notable changes to libre will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v2.0.1] - 2021-04-22

### Fixed

- tmr: fix FreeBSD and OpenBSD [#97]
- mk: fix clang analyze CFLAGS

### Changed

- tls: different return values for tls_get_ca_chain_field() [#94]


## [v2.0.0] - 2021-04-10

### Added

- .gitignore: add ctags and vim swp files to gitignore [#31]
- tls: add tls_add_capem() for adding CA cert as PEM string [#33]
- httpauth: Add digest support for http clients [#33]
- httpauth: Add basic authentication for HTTP clients [#33]
- dns: add set function for DNS config [#33]
- http/client: support IPv6 [#33]
- http/client: use const parameter for set laddr(6) functions [#33]
- http/client: add set function for timeout [#33]
- http/client: add http_client_add_capem() [#33]
- http/client: add set functions for client certificate and private key [#33]
- http: add HTTP request connection with authorization [#33]
- http: setting of timeouts for http client [#35]
- http: set default path for http requests [#35]
- tls: set selfsigned Elliptic Curve (EC) function [#17]
- tls: extend server verification by host name check (SNI) [#45]
- jbuf: adapative jitter buffer [#41]
- tmr: add tmr_jiffies_usec() - get accurate microseconds [#52]
- fmt: add pl_i32() that converts pl to int32_t [#60]
- fmt: add pl_i64() that converts pl to int64_t [#60]
- mk/re: add C11 and Atomic detection [#61]
- ci: add abi check [#39]
- trace: add re_trace api [#48]
- Add function that resets the timeout timer for a connection of the HTTP server. [#88]
- add error trace helpers [#87]
- sip/auth: add algorithm=MD5 [#86]
- sys: filesystem isdir function
- tls: use ENOENT in tls_add_cafile_path as error code
- tls: more generic function to set cafile and capath
- mk: add .so name versioning, resolves #32
- mk/re: add clang shorten-64-to-32 warning
- mk/re: document new library/header prioritised order with custom SYSROOT
- mk/re: info double colon rule (#64) [#64]
- udp: Add function udp_open for socket without bind
- rtp: Add rtp_open which creates an RTP object only for sending. [#77]
- sip: add decode function for SIP transport
- sip: SIP/TLS Server Name Indication (#67) [#67]
- transp: add flag to disable SIP TLS server verification [#76]

### Removed

- openssl: remove obsolete function tls_set_hostname() [#33]
- mk/re: remove gcc 2.x/3.x support [#58]
- ci: drop ubuntu 16.04 support - end of life

### Changed

- http/client: cleanup doxygen [#33]
- http/client: use host of http_req for the host name validation [#37]
- main: disable MAIN_DEBUG, TMR_DEBUG and increase MAX_BLOCKING to 500ms [#43]
- sipreg: dont't force digest challenge for register [#49]
- mk/re: do not override LIBRE_INC, LIBRE_SO and LIBRE_PATH [#62]
- readme: update supported systems and add tiers [#81]
- tls: use ENOTDIR in tls_add_cafile_path if capath is not a dir [#84]
- tls: check capath is directory
- net: get default source addr from udp local test socket [#66]
- Update chklist.c [#70]
- Update icesdp.c [#69]
- mk: cross build changes (#63) [#63]
- sip: use sip_transp_decode() [#71]
- tls: tls_get_issuer/subject return the info of the first loaded ca [#80]

### Fixed

- dns/client: fix HAVE_INET6 and win32/vcxproj: updates [#28]
- http: fix segfault in response.c [#35]
- http/request: parameter NULL check for http_reqconn_send() [#37]
- http/client: fix conn_idle [#46]
- http/httpreq: mem leak fix [#47]
- sip/request: fix msg->scode null pointer dereference
- rtmp/conn: initialize err
- mk/re: fix LIBRE_SO static detection
- dns/res: Properly process IPV4 and IPV6 addresses (DARWIN) [#56]
- sip/keepalive: fix codeql cpp/integer-multiplication-cast-to-long
- fmt/time: fix codeql gmtime warning
- mk/re: fix gcc 4.x and newer compiler warnings
- sys: add _BSD_SOURCE 1 for compatibility reasons [#92]
- fix weak self-signed certificates [#68]
- net/tls: fixing shorten-64-to-32 warnings [#65]
- http: add missing newline to warning [#78]
- http: fix file read for client certificates
- mk/re: do not override LIBRE_INC, LIBRE_SO and LIBRE_PATH [#62]
- tls: safety NULL pointer check in tls_add_ca() [#79]

### Contributors (many thanks)

- [sreimers](https://github.com/sreimers)
- [cHuberCoffee](https://github.com/cHuberCoffee)
- [RobertMi21](https://github.com/RobertMi21)
- [cspiel1](https://github.com/cspiel1)
- [alfredh](https://github.com/alfredh)
- [fippo](https://github.com/fippo)
- [jurjen-van-dijk](https://github.com/jurjen-van-dijk)
- [rolizo](https://github.com/rolizo)


## [v1.1.0] - 2020-10-04

### Added

- tls: functions to get the certificate issuer and subject [#18]
- uri: Added path field to struct uri and its decode to uri_decode [#22]
- tcp: add tcp_connect_bind [#24]
- http: support bind to laddr in http_request [#24]
- sipreg: support Cisco REGISTER keep-alives [#19]
- sip: websocket support [#26]

### Fixed

- tls/openssl: fix X509_NAME win32/wincrypt.h conflict
- dns: listen on IPv4 and IPv6 socket [#27]
- main: fix/optimize windows file descriptors [#25]

### Contributors (many thanks)

- Alfred E. Heggestad
- Christian Spielberger
- Christoph Huber
- Franz Auernigg
- Juha Heinanen
- johnjuuljensen
- Sebastian Reimers


## [v1.0.0] - 2020-09-08

### Added

- sip: add trace
- sdp: sdp_media_disabled API function [#2]
- tls: add tls_set_selfsigned_rsa [#6]
- tls: add functions to verify server cert, purpose and hostname [#10]
- http: client should set SNI [#10]
- http: client should use tls functions to verify server certs, purpose
  and hostname [#10]
- sipreg: add proxy expires field and get function [#13]
- sipreg: make re-register interval configurable [#13]

### Changed

- debian: Automatic cleanup after building debian package

### Fixed

- Set SDK path (SYSROOT) using xcrun (fix building on macOS 10.14)
- tcp: close socket on windows if connection is aborted or reset [#1]
- rtmp: Fix URL path parsing (creytiv#245)
- ice: various fixes [baresip/baresip#925]
- openssl/tls: replace deprecated openssl 1.1.0 functions [#5]

### Contributors (many thanks)

- Alfred E. Heggestad
- Christian Spielberger
- Christoph Huber
- Franz Auernigg
- juha-h
- Juha Heinanen
- Richard Aas
- Sebastian Reimers

[#97]: https://github.com/baresip/re/pull/97
[#94]: https://github.com/baresip/re/pull/94
[#81]: https://github.com/baresip/re/pull/81
[#48]: https://github.com/baresip/re/pull/48
[#92]: https://github.com/baresip/re/pull/92
[#88]: https://github.com/baresip/re/pull/88
[#87]: https://github.com/baresip/re/pull/87
[#86]: https://github.com/baresip/re/pull/86
[#84]: https://github.com/baresip/re/pull/84
[#83]: https://github.com/baresip/re/pull/83
[#82]: https://github.com/baresip/re/pull/82
[#80]: https://github.com/baresip/re/pull/80
[#79]: https://github.com/baresip/re/pull/79
[#78]: https://github.com/baresip/re/pull/78
[#77]: https://github.com/baresip/re/pull/77
[#76]: https://github.com/baresip/re/pull/76
[#39]: https://github.com/baresip/re/pull/39
[#66]: https://github.com/baresip/re/pull/66
[#74]: https://github.com/baresip/re/pull/74
[#67]: https://github.com/baresip/re/pull/67
[#71]: https://github.com/baresip/re/pull/71
[#70]: https://github.com/baresip/re/pull/70
[#69]: https://github.com/baresip/re/pull/69
[#68]: https://github.com/baresip/re/pull/68
[#65]: https://github.com/baresip/re/pull/65
[#63]: https://github.com/baresip/re/pull/63
[#64]: https://github.com/baresip/re/pull/64
[#62]: https://github.com/baresip/re/pull/62
[#61]: https://github.com/baresip/re/pull/61
[#60]: https://github.com/baresip/re/pull/60
[#58]: https://github.com/baresip/re/pull/58
[#56]: https://github.com/baresip/re/pull/56
[#52]: https://github.com/baresip/re/pull/52
[#49]: https://github.com/baresip/re/pull/49
[#47]: https://github.com/baresip/re/pull/47
[#46]: https://github.com/baresip/re/pull/46
[#45]: https://github.com/baresip/re/pull/45
[#43]: https://github.com/baresip/re/pull/43
[#41]: https://github.com/baresip/re/pull/41
[#37]: https://github.com/baresip/re/pull/37
[#35]: https://github.com/baresip/re/pull/35
[#33]: https://github.com/baresip/re/pull/33
[#31]: https://github.com/baresip/re/pull/31
[#28]: https://github.com/baresip/re/pull/28
[#27]: https://github.com/baresip/re/pull/27
[#26]: https://github.com/baresip/re/pull/26
[#25]: https://github.com/baresip/re/pull/25
[#19]: https://github.com/baresip/re/pull/19
[#24]: https://github.com/baresip/re/pull/24
[#22]: https://github.com/baresip/re/pull/22
[#18]: https://github.com/baresip/re/pull/18
[#17]: https://github.com/baresip/re/pull/17
[#13]: https://github.com/baresip/re/pull/13
[#10]: https://github.com/baresip/re/pull/10
[#6]: https://github.com/baresip/re/pull/6
[#5]: https://github.com/baresip/re/pull/5
[#2]: https://github.com/baresip/re/pull/2
[#1]: https://github.com/baresip/re/pull/1

[Unreleased]: https://github.com/baresip/re/compare/v2.0.1...HEAD
[v2.0.1]: https://github.com/baresip/re/compare/v2.0.0...v2.0.1
[v2.0.0]: https://github.com/baresip/re/compare/v1.1.0...v2.0.0
[v1.1.0]: https://github.com/baresip/re/compare/v1.0.0...v1.1.0
[v1.0.0]: https://github.com/baresip/re/compare/v0.6.1...v1.0.0
