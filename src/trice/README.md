ICE-NOTES:
---------



----------------------------------
Application layer:

- Can handle any modes (Full, Ice, Trickle)
- Can implement any nomination-type (regular, aggressive)
- Can encode/decode SDP attributes
- Must gather all candidates (including STUN/TURN servers)
- Application can choose the Default Local Candidate
- Application can choose the Default Remote Candidate
- Can measure RTT end-to-end
- Can apply a STUN consent timer on top of ICE
- the application should have the freedom to choose any selected candidate-pair
- can install Keep-Alive timer (Binding Indication) for any pairs
- can install a consent timer for any pair


----------------------------------
ICE layer:

- All modes (Full-ICE and Trickle-ICE) are implemented
- ICE-lite is NOT supported
- agnostic to modes (Full, Trickle)
- agnostic to nomination-type (regular, aggressive)
- SDP encoding and decoding of ICE-relevant attributes
- can handle between 1 and 2 components per media-stream
- gathering: No candidate gathering, must be done in App
- agnostic to transport protocol (should handle both UDP and TCP)
- rel-addr (related address) is supported, but it is not used in the logic
- ICE-stack does not choose the Default Local Candidate
- ICE-stack does not choose the Default Remote Candidate
- no TURN client
- Each local candidate can have its own listen address/port. Yes
- Support for UDP-transport
- Support for TCP-transport
- Support for IPv4 and IPv6
- modular design with building blocks.
- check all components before calling estabh ? no.
- no support for "default" candidate/candidate-pair
- component object: NO
- selected pair: NO  
- must be able to support custom UDP/TCP-transport via helpers


----------------------------------
Interop:

OK - Firefox 31.0
OK - Firefox 35.0
OK - Firefox 36.0
OK - Chrome 41
OK - Chrome 58


TODO:

done - remove ICE-lite mode
done - remove rel-addr from ICE-code
done - interop testing with Chrome
done - interop testing with Firefox - seems to be working with 31.0
done - Firefox: test with trickling candidates over Websock
done - add support for TCP-candidates (test with Chrome)
done - make a new test-client (reicec) and test on a public server
done - do we need to support LITE at all? No.
done - split EOC flag into local_eoc and remote_eoc
done - send triggered request from stunsrv
done - new module "icesdp" for SDP encoding/decoding
done - add a new module "shim" (RFC 4571)
     - ICE module should be Conncheck-only, no data-transport
     - test_ice_tcp: S-O not working on Linux
done - check when adding PRFLX that EOC-flag is set/unset (not needed)
done - move use_cand flag to checklist_start/send_conncheck ?
     - verify that APP can grab udp/tcp-sock
     - consider moving pacing-logic to application?




Architecture Diagram:
--------------------



```

  .-------.                  .-------. 
  |  App  |                  |  App  |
  '-------'                  '-------'
      |                          |           \
      |        .--------.        |           |
      +--------+  STUN  +--------+           |
      |        '--------'        |           | "ICE-layer"
      |                      .-------.       |
      |                      | SHIM  |       |
      |                      '-------'       |
      |                          |           /
  .-------.                  .-------.
  |  UDP  |                  |  TCP  |
  '-------'                  '-------'
      |                          |
      !                          !



```
