package dkrcrypt

// The HIGHT Block cipher from KISA
// Copyright (c) 2012 Damian Gryski <damian@gryski.com>
// Licensed under the GPLv3 or, at your option, any later version.

/*

References:

http://tools.ietf.org/html/draft-kisa-hight-00
http://www.iacr.org/cryptodb/archive/2006/CHES/04/04.pdf
http://seed.kisa.or.kr/kor/hight/hightInfo.jsp

*/

import (
	"strconv"
)

// A HightCipher is an instance of HIGHT encryption using a particular key.
type HightCipher struct {
	wk [8]byte   // whitened keys
	sk [128]byte // subkeys
}

type KeySizeError int

func (k KeySizeError) Error() string {
	return "dkrcrypt: invalid key size " + strconv.Itoa(int(k))
}

// NewHight creates and returns a new HightCipher.
// The key argument should be 16 bytes.
func NewHight(key []byte) (*HightCipher, error) {
	c := new(HightCipher)

	if klen := len(key); klen != 16 {
		return nil, KeySizeError(klen)
        }

	c.whiten(key)
	c.subkeys(key)
	return c, nil
}

// BlockSize returns the Hight block size.  It is needed to satisfy the Block interface in crypto/cipher.
func (c *HightCipher) BlockSize() int { return 8 }

// rotate left
func rotl8(x byte, r byte) byte {
	return (x << r) | (x >> (8 - r))
}

// F0, from the specification
func f0(x byte) byte {
	return rotl8(x, 1) ^ rotl8(x, 2) ^ rotl8(x, 7)
}

// F1, from the specification
func f1(x byte) byte {
	return rotl8(x, 3) ^ rotl8(x, 4) ^ rotl8(x, 6)
}

// Encrypt encrypts the 8-byte block in src and stores the resulting ciphertext in dst.
func (c *HightCipher) Encrypt(dst, src []byte) {

	// numbering looks off here, because the plaintext is stored msb, but
	// having lsb makes our life easier
	x := [...]byte{
		src[7] + c.wk[0], // p0
		src[6],           // p1
		src[5] ^ c.wk[1], // p2
		src[4],           // p3
		src[3] + c.wk[2], // p4
		src[2],           // p5
		src[1] ^ c.wk[3], // p6
		src[0],           // p0
	}

	for i := 0; i < 31; i++ {
		x00 := x[7] ^ (f0(x[6]) + c.sk[4*i+3])
		x[7] = x[6]
		x[6] = x[5] + (f1(x[4]) ^ c.sk[4*i+2])
		x[5] = x[4]
		x[4] = x[3] ^ (f0(x[2]) + c.sk[4*i+1])
		x[3] = x[2]
		x[2] = x[1] + (f1(x[0]) ^ c.sk[4*i+0])
		x[1] = x[0]
		x[0] = x00
	}

	// last round
	dst[6] = x[1] + (f1(x[0]) ^ c.sk[124])
	dst[4] = x[3] ^ (f0(x[2]) + c.sk[125])
	dst[2] = x[5] + (f1(x[4]) ^ c.sk[126])
	dst[0] = x[7] ^ (f0(x[6]) + c.sk[127])

	// whitening
	dst[7] = x[0] + c.wk[4]
	dst[5] = x[2] ^ c.wk[5]
	dst[3] = x[4] + c.wk[6]
	dst[1] = x[6] ^ c.wk[7]
}

// Decrypt decrypts the 8-byte block in src and stores the resulting plaintext in dst.
func (c *HightCipher) Decrypt(dst, src []byte) {

	// whitening
	x := [...]byte{
		src[7] - c.wk[4], // c0
		src[6],           // c1
		src[5] ^ c.wk[5], // c2
		src[4],           // c3
		src[3] - c.wk[6], // c4
		src[2],           // c5
		src[1] ^ c.wk[7], // c6
		src[0],           // c7
	}

	// undo last round
	x[1] = x[1] - (f1(x[0]) ^ c.sk[124])
	x[3] = x[3] ^ (f0(x[2]) + c.sk[125])
	x[5] = x[5] - (f1(x[4]) ^ c.sk[126])
	x[7] = x[7] ^ (f0(x[6]) + c.sk[127])

	for i := 30; i >= 0; i-- {
		x00 := x[0]
		x[0] = x[1]
		x[1] = x[2] - (f1(x[1]) ^ c.sk[4*i+0])
		x[2] = x[3]
		x[3] = x[4] ^ (f0(x[3]) + c.sk[4*i+1])
		x[4] = x[5]
		x[5] = x[6] - (f1(x[5]) ^ c.sk[4*i+2])
		x[6] = x[7]
		x[7] = x00 ^ (f0(x[7]) + c.sk[4*i+3])
	}

	// undo initial whitening
	dst[7] = x[0] - c.wk[0] // p0
	dst[6] = x[1]           // p1
	dst[5] = x[2] ^ c.wk[1] // p2
	dst[4] = x[3]           // p3
	dst[3] = x[4] - c.wk[2] // p4
	dst[2] = x[5]           // p5
	dst[1] = x[6] ^ c.wk[3] // p6
	dst[0] = x[7]           // p7
}

func (c *HightCipher) whiten(mk []byte) {

	for i := 0; i < 4; i++ {
		c.wk[i] = mk[16-i-12-1]
	}

	for i := 4; i < 8; i++ {
		c.wk[i] = mk[16-i+4-1]
	}
}

// This table doesn't change, so rather that recompute it every time we need to
// compute subkeys, we just build it once.  The code to create it was:

/*
   s = 0x5A
   d[0] = s
   for i := 1; i < 128; i++ {
           s = (s >> 1) | (((s & 1) ^ ((s & (1 << 3)) >> 3)) << 6)
           d[i] = s
   }
*/

var delta = []byte{
	0x5a, 0x6d, 0x36, 0x1b, 0x0d, 0x06, 0x03, 0x41,
	0x60, 0x30, 0x18, 0x4c, 0x66, 0x33, 0x59, 0x2c,
	0x56, 0x2b, 0x15, 0x4a, 0x65, 0x72, 0x39, 0x1c,
	0x4e, 0x67, 0x73, 0x79, 0x3c, 0x5e, 0x6f, 0x37,
	0x5b, 0x2d, 0x16, 0x0b, 0x05, 0x42, 0x21, 0x50,
	0x28, 0x54, 0x2a, 0x55, 0x6a, 0x75, 0x7a, 0x7d,
	0x3e, 0x5f, 0x2f, 0x17, 0x4b, 0x25, 0x52, 0x29,
	0x14, 0x0a, 0x45, 0x62, 0x31, 0x58, 0x6c, 0x76,
	0x3b, 0x1d, 0x0e, 0x47, 0x63, 0x71, 0x78, 0x7c,
	0x7e, 0x7f, 0x3f, 0x1f, 0x0f, 0x07, 0x43, 0x61,
	0x70, 0x38, 0x5c, 0x6e, 0x77, 0x7b, 0x3d, 0x1e,
	0x4f, 0x27, 0x53, 0x69, 0x34, 0x1a, 0x4d, 0x26,
	0x13, 0x49, 0x24, 0x12, 0x09, 0x04, 0x02, 0x01,
	0x40, 0x20, 0x10, 0x08, 0x44, 0x22, 0x11, 0x48,
	0x64, 0x32, 0x19, 0x0c, 0x46, 0x23, 0x51, 0x68,
	0x74, 0x3a, 0x5d, 0x2e, 0x57, 0x6b, 0x35, 0x5a,
}

func (c *HightCipher) subkeys(mk []byte) {

	for i := 0; i < 8; i++ {

		for j := 0; j < 8; j++ {
			k := j - i
			if k < 0 {
				k += 8
			}
			c.sk[16*i+j] = mk[16-k-1] + delta[16*i+j]
		}

		for j := 0; j < 8; j++ {
			k := j - i
			if k < 0 {
				k += 8
			}
			c.sk[16*i+j+8] = mk[16-k-8-1] + delta[16*i+j+8]
		}

	}
}
