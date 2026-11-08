#!/usr/bin/env nu
# Real responses of public DoH servers over HTTP/2 (RFC 8484), saved as <id>.headers (`curl -D`) and <id>.body, the
# DNS message. The queries have ID 0 and an OPT record advertising 1232 bytes, as `dedens` sends them. Run from this
# directory: `nu capture.nu`. Never edit the saved files by hand. `curl --http3` is not in every curl: the system's
# has none, so HTTP/3 captures wait for one that has.
# Tested by `crates/dedens-net/tests/doh.rs`.

const captures = [
    {id: cloudflare_a, url: "https://cloudflare-dns.com/dns-query", name: [example com], type: 1, method: GET}
    {id: cloudflare_nxdomain, url: "https://cloudflare-dns.com/dns-query", name: [nonexistent invalid], type: 1, method: GET}
    {id: google_aaaa, url: "https://dns.google/dns-query", name: [cloudflare com], type: 28, method: GET}
    {id: google_a_post, url: "https://dns.google/dns-query", name: [example com], type: 1, method: POST}
    {id: quad9_mx, url: "https://dns.quad9.net/dns-query", name: [gmail com], type: 15, method: GET}
    {id: adguard_https, url: "https://dns.adguard-dns.com/dns-query", name: [cloudflare com], type: 65, method: POST}
]

# The wire form of a query for `name` (labels) and `type`, below 256: ID 0, RD, one question, one OPT.
def query [name: list<string>, type: int]: nothing -> binary {
    let labels = $name | each {|label| bytes build ($label | str length | into binary | first 1) ($label | encode utf-8) }
    bytes build 0x[0000 0100 0001 0000 0000 0001] ...$labels 0x[00 00] ($type | into binary | first 1) 0x[0001] 0x[00 0029 04d0 00000000 0000]
}

for c in $captures {
    let wire = query $c.name $c.type
    let accept = "accept: application/dns-message"
    if $c.method == GET {
        let dns = $wire | encode base64 --url --nopad
        ^curl --silent --show-error --fail --http2 -D $"($c.id).headers" -o $"($c.id).body" -H $accept $"($c.url)?dns=($dns)"
    } else {
        $wire | ^curl --silent --show-error --fail --http2 -D $"($c.id).headers" -o $"($c.id).body" -H $accept -H "content-type: application/dns-message" --data-binary @- $c.url
    }
    $wire | save --force $"($c.id).query"
}
