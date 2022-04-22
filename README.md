# Validity90


# State of this fork

First: it is not finishied and I have run into a substantial issue that I cannot seem to solve

I attempted to properly connect to the sensor instead of using hard codded buffers of data. Most of the work was done by the makers of [python-validity](https://github.com/uunicorn/python-validity) and this was mostly rewriting it in C.


I have managed to get all the way up to the final packet of the connection handshake, but then I recive the error code that the spec defines as "Bad HMAC".
I have verified all the previous packets, I have rewritted and verified the hashing and encryption algorithms and tried every debugging avenue that I can think of. 

My work is in prototype/main_rewrite.c, prototype/tls.c and prototype/tls.h, they can be built using Makefile/prototype.

If you do make any progress or figure out anything please open an issue.

# Rest of original readme

This project aims on reverse engineering protocol of Validity 138a:0090, 138a:0094, 138a:0097, 06cb:0081, 06cb:009a fingerprint readers, creating specification and FLOSS libfprint driver.

## Discussions

Main chat of this project: [![Gitter](https://img.shields.io/gitter/room/nwjs/nw.js.svg)](https://gitter.im/Validity90/Lobby?utm_source=share-link&utm_medium=link&utm_campaign=share-link)

libfrprint issue: [https://gitlab.freedesktop.org/libfprint/libfprint/issues/54](https://gitlab.freedesktop.org/libfprint/libfprint/issues/54)

Lenovo forums: [https://forums.lenovo.com/t5/Linux-Discussion/Validity-Fingerprint-Reader-Linux/td-p/3352145](https://forums.lenovo.com/t5/Linux-Discussion/Validity-Fingerprint-Reader-Linux/td-p/3352145)

## Notable files

1. [spec.md](spec.md) - Specification draft, the main work goes here right now.
2. [dissector.lua](dissector.lua) - Wireshark dissector for decrypting communication after key exchange.
3. ~[libfprint directory](libfprint) - libfprint repo with this driver integrated~ Not ready at the moment.
4. [prototype](prototype) - Standalone prototype(extremly ugly code, would be completly rewritten for driver)

## Testing

[Prototype](prototype) testers are needed, please share your result and join us in our [Gitter](https://gitter.im/Validity90/Lobby?utm_source=share-link&utm_medium=link&utm_campaign=share-link).

## Status

|   Device  | Status |
|-----------|--------|
| 138a:0090 | Scan, Image output, Internal DB check works in prototype. There is also a match-on-host [libfprint driver](https://github.com/3v1n0/libfprint) by @3v1n0 based on prototype source(138a:0090 only). You can use it untill proper unified driver is available. |
| 138a:0097 | Scan, Internal DB check works in prototype |
| 138a:0094 | Doesn't work yet, but looks promising. I will try to work on it after 90/97 |
| 06cb:0081 | So far looks identical to 138a:0094 |
| 06cb:009a | Init works, leds work, scan doesn't work yet |
| 138a:0091 | Different protocol, out of scope for this project. Check out [Validity91](https://github.com/hmaarrfk/Validity91) which aims to reverse engineer it.|


| 		      Task       			| Specification/Analysis  | Prototype   | Driver 	    |
|---------------------------|-------------------------|-------------|-------------|
| Initialization  		      | Done 					          | Done	 	    | Not Started |
| Configuration/Reconfig    | In progress 	          | In progress | Not Started |
| Pre TLS key exchange 	    | In progress 				    | Done        | Not Started |
| TLS 			                | Done 						        | Done  	    | Not Started |
| 90: Ops: scan, LED, etc| In progress  			      | Scan, LED works  | Not Started |
| 97: Ops: enroll, check, reset, LED, etc| In progress  			      | Check works  | Not Started |
| Image format  		        | In progress  			      | Done        | Not Started |

## Donations

Please consider donating to support the development.  
With paypal: [![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.me/nmikhailov/0usd)  
With BTC: 1AsoCUGNVniBSBS359u2wKrA2CZiTgKZkM  
With ETH: 0x005D8d9b5609b9A3Ec8B3cBd463a949405A8d621  
