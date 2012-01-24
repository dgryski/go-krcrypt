package dkrcrypt

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
}

func TestSEEDEncrypt(t *testing.T) {

	for _, v := range seedTestVectors {
		h, _ := NewSEED(v.key)

		var c [16]byte

		h.Encrypt(c[:], v.plain)

		if bytes.Compare(v.cipher, c[:]) != 0 {
			t.Errorf("seed encrypt failed: got %#v wanted %#v\n", c, v.cipher)
		}

		/*
			h.Decrypt(p[:], c[:])

			if bytes.Compare(v.plain, p[:]) != 0 {
				t.Errorf("hight decrypt failed: got %#v wanted %#v\n", p, v.plain)
			}
		*/
	}
}