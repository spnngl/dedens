#!/usr/bin/env nu
# Real CoAP datagrams: aiocoap 0.4.17 as client and as server on the loopback address, a logging UDP proxy between
# them (`capture.py`). It saves each exchange as <id>.txt: a `#` line with the command, then a line a datagram
# (milliseconds since the first, `c2s` client to server or `s2c` server to client, `-lost` if the proxy dropped it,
# the datagram in hex). The bodies are real: the DoC query and response are the quad9 MX files of `../doh`, the long
# body is the start of RFC 9953. Run from this directory: `nu capture.nu`. Never edit the saved files by hand.
# Tested by `crates/dedens-net/tests/coap.rs`. The `libcoap_*` files are libcoap 4.3.5b
# (`brew install libcoap`), made by `capture_libcoap.py` (same format; its `coap-server` and `coap-client` behind the same
# proxy): run `uv run --with aiocoap==0.4.17 python capture_libcoap.py`. Its bodies are real DNS answers saved with
# `dedens @https://dns.google/dns-query cloudflare.com TXT +dnssec --save-wire` (`dns_txt.body`, 2808 bytes) and the
# same for `. DNSKEY` (`dns_dnskey.body`, 1280 bytes).

^uv run --with aiocoap==0.4.17 python capture.py
