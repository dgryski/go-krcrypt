package dkrcrypt

import (
	"bytes"
	"testing"
)

// http://tools.ietf.org/html/rfc5794 "A Description of the ARIA Encryption Algorithm"
var ariaTestVectors = []struct {
	key    []byte
	plain  []byte
	cipher []byte
}{
	{[]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, []byte{0xd7, 0x18, 0xfb, 0xd6, 0xab, 0x64, 0x4c, 0x73, 0x9d, 0xa9, 0x5f, 0x3b, 0xe6, 0x45, 0x17, 0x78}},
}

// make sure we can encrypt to produce our test vectors, and decrypt to produce the original plaintext.
func TestAriaEncrypt(t *testing.T) {

	for _, v := range ariaTestVectors {
		a, _ := NewAria(v.key)

		var c, p [16]byte

		a.Encrypt(c[:], v.plain)

		if bytes.Compare(v.cipher, c[:]) != 0 {
			t.Errorf("aria encrypt failed: got %#v wanted %#v\n", c, v.cipher)
		}

		a.Decrypt(p[:], c[:])

		if bytes.Compare(v.plain, p[:]) != 0 {
			t.Errorf("aria decrypt failed: got %#v wanted %#v\n", p, v.plain)
		}
	}
}
