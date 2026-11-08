// Package bench measures github.com/miekg/dns, the codec of CoreDNS, on the captured responses the Rust
// benches use (D14), so the numbers sit next to `cargo bench -p dedens-bench`.
package bench

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
)

// The cases of crates/dedens-bench/src/lib.rs.
var cases = []string{"a", "mx", "txt_large"}

func wire(b *testing.B, name string) []byte {
	b.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "proto", name+".bin"))
	if err != nil {
		b.Fatal(err)
	}
	return data
}

func unpacked(b *testing.B, name string) *dns.Msg {
	b.Helper()
	m := new(dns.Msg)
	if err := m.Unpack(wire(b, name)); err != nil {
		b.Fatal(err)
	}
	// Equal work: dedens, hickory-proto and domain compress names.
	m.Compress = true
	return m
}

// Decode: the whole message into typed records.
func BenchmarkDecodeMiekg(b *testing.B) {
	for _, name := range cases {
		data := wire(b, name)
		b.Run(name, func(b *testing.B) {
			for b.Loop() {
				if err := new(dns.Msg).Unpack(data); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// Encode into a buffer reused across iterations, like encode_dedens.
func BenchmarkEncodeMiekg(b *testing.B) {
	for _, name := range cases {
		m := unpacked(b, name)
		buf := make([]byte, 4096)
		b.Run(name, func(b *testing.B) {
			for b.Loop() {
				if _, err := m.PackBuffer(buf); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// Encode into a fresh slice, like the *_to_vec benches.
func BenchmarkEncodeMiekgToVec(b *testing.B) {
	for _, name := range cases {
		m := unpacked(b, name)
		b.Run(name, func(b *testing.B) {
			for b.Loop() {
				if _, err := m.Pack(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
