package krcrypt

import (
	"bytes"
	"testing"
)

var seedTestVectors = []struct {
	key    []byte
	plain  []byte
	cipher []byte
}{
	{[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, []byte{0x5e, 0xba, 0xc6, 0xe0, 0x05, 0x4e, 0x16, 0x68, 0x19, 0xaf, 0xf1, 0xcc, 0x6d, 0x34, 0x6c, 0xdb}},
	{[]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, []byte{0xc1, 0x1f, 0x22, 0xf2, 0x01, 0x40, 0x50, 0x50, 0x84, 0x48, 0x35, 0x97, 0xe4, 0x37, 0x0f, 0x43}},
	{[]byte{0x47, 0x06, 0x48, 0x08, 0x51, 0xe6, 0x1b, 0xe8, 0x5d, 0x74, 0xbf, 0xb3, 0xfd, 0x95, 0x61, 0x85}, []byte{0x83, 0xa2, 0xf8, 0xa2, 0x88, 0x64, 0x1f, 0xb9, 0xa4, 0xe9, 0xa5, 0xcc, 0x2f, 0x13, 0x1c, 0x7d}, []byte{0xee, 0x54, 0xd1, 0x3e, 0xbc, 0xae, 0x70, 0x6d, 0x22, 0x6b, 0xc3, 0x14, 0x2c, 0xd4, 0x0d, 0x4a}},
	{[]byte{0x28, 0xdb, 0xc3, 0xbc, 0x49, 0xff, 0xd8, 0x7d, 0xcf, 0xa5, 0x09, 0xb1, 0x1d, 0x42, 0x2b, 0xe7}, []byte{0xb4, 0x1e, 0x6b, 0xe2, 0xeb, 0xa8, 0x4a, 0x14, 0x8e, 0x2e, 0xed, 0x84, 0x59, 0x3c, 0x5e, 0xc7}, []byte{0x9b, 0x9b, 0x7b, 0xfc, 0xd1, 0x81, 0x3c, 0xb9, 0x5d, 0x0b, 0x36, 0x18, 0xf4, 0x0f, 0x51, 0x22}},
}

func TestSEEDEncrypt(t *testing.T) {

	for _, v := range seedTestVectors {
		h, _ := NewSEED(v.key)

		var c, p [16]byte

		h.Encrypt(c[:], v.plain)

		if !bytes.Equal(v.cipher, c[:]) {
			t.Errorf("seed encrypt failed: got %#v wanted %#v\n", c, v.cipher)
		}

		h.Decrypt(p[:], c[:])

		if !bytes.Equal(v.plain, p[:]) {
			t.Errorf("seed decrypt failed: got %#v wanted %#v\n", p, v.plain)
		}
	}
}
