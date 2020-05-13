// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sha256d implements the SHA256d hash algorithms as defined
// in FIPS 180-4.
package sha256d

import (
	"encoding/binary"
)

// The size of a SHA256 checksum in bytes.
const Size = 32

// The blocksize of SHA256 in bytes.
const BlockSize = 64

const (
	chunk = 64
	init0 = 0x6A09E667
	init1 = 0xBB67AE85
	init2 = 0x3C6EF372
	init3 = 0xA54FF53A
	init4 = 0x510E527F
	init5 = 0x9B05688C
	init6 = 0x1F83D9AB
	init7 = 0x5BE0CD19
)

// digest represents the partial evaluation of a checksum.
type Digest struct {
	h   [8]uint32
	x   [chunk]byte
	nx  int
	len uint64
}

func (d *Digest) Reset() {
	d.h[0] = init0
	d.h[1] = init1
	d.h[2] = init2
	d.h[3] = init3
	d.h[4] = init4
	d.h[5] = init5
	d.h[6] = init6
	d.h[7] = init7
	d.nx = 0
	d.len = 0
}

// New returns a new Digest computing the SHA256d checksum.
func New() *Digest {
	d := new(Digest)
	d.Reset()
	return d
}

func (d *Digest) Size() int {
	return Size
}

func (d *Digest) BlockSize() int { return BlockSize }

func (d *Digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == chunk {
			block(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= chunk {
		n := len(p) &^ (chunk - 1)
		block(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d *Digest) Sum(in []byte) []byte {
	// Make a copy of d so that caller can keep writing and summing.
	d0 := *d
	hash := d0.checkSum()
	return append(in, hash[:]...)
}

func (d *Digest) checkSum() [Size]byte {
	len := d.len
	// Padding. Add a 1 bit and 0 bits until 56 bytes mod 64.
	var tmp [64]byte
	tmp[0] = 0x80
	if len%64 < 56 {
		d.Write(tmp[0 : 56-len%64])
	} else {
		d.Write(tmp[0 : 64+56-len%64])
	}

	// Length in bits.
	len <<= 3
	binary.BigEndian.PutUint64(tmp[:], len)
	d.Write(tmp[0:8])

	if d.nx != 0 {
		panic("d.nx != 0")
	}

	tmp = [chunk]byte{}
	binary.BigEndian.PutUint32(tmp[0:], d.h[0])
	binary.BigEndian.PutUint32(tmp[4:], d.h[1])
	binary.BigEndian.PutUint32(tmp[8:], d.h[2])
	binary.BigEndian.PutUint32(tmp[12:], d.h[3])
	binary.BigEndian.PutUint32(tmp[16:], d.h[4])
	binary.BigEndian.PutUint32(tmp[20:], d.h[5])
	binary.BigEndian.PutUint32(tmp[24:], d.h[6])
	binary.BigEndian.PutUint32(tmp[28:], d.h[7])
	tmp[Size] = 0x80
	// Length in bits.
	tmp[chunk-2] = 1
	d.Reset()
	d.Write(tmp[:])

	var digest [Size]byte

	binary.BigEndian.PutUint32(digest[0:], d.h[0])
	binary.BigEndian.PutUint32(digest[4:], d.h[1])
	binary.BigEndian.PutUint32(digest[8:], d.h[2])
	binary.BigEndian.PutUint32(digest[12:], d.h[3])
	binary.BigEndian.PutUint32(digest[16:], d.h[4])
	binary.BigEndian.PutUint32(digest[20:], d.h[5])
	binary.BigEndian.PutUint32(digest[24:], d.h[6])
	binary.BigEndian.PutUint32(digest[28:], d.h[7])

	return digest
}

// Sum returns the SHA256d checksum of the data.
func Sum(data []byte) [Size]byte {
	var d Digest
	d.Reset()
	d.Write(data)
	return d.checkSum()
}
