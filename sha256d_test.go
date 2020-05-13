// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// SHA256 hash algorithm. See FIPS 180-2.

package sha256d

import (
	"crypto/rand"
	"fmt"
	"io"
	"testing"
)

type sha256dTest struct {
	out string
	in  string
}

var golden = []sha256dTest{
	{"5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456", ""},
	{"bf5d3affb73efd2ec6c36ad3112dd933efed63c4e1cbffcfa88e2759c144f2d8", "a"},
	{"a1ff8f1856b5e24e32e3882edd4a021f48f28a8b21854b77fdef25a97601aace", "ab"},
	{"4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358", "abc"},
	{"7e9c158ecd919fa439a7a214c9fc58b85c3177fb1613bdae41ee695060e11bc6", "abcd"},
	{"1d72b6eb7ba8b9709c790b33b40d8c46211958e13cf85dbcda0ed201a99f2fb9", "abcde"},
	{"ce65d4756128f0035cba4d8d7fae4e9fa93cf7fdf12c0f83ee4a0e84064bef8a", "abcdef"},
	{"dad6b965ad86b880ceb6993f98ebeeb242de39f6b87a458c6510b5a15ff7bbf1", "abcdefg"},
	{"b9b12e7125f73fda20b8c4161fb9b4b146c34cf88595a1e0503ca2cf44c86bc4", "abcdefgh"},
	{"546db09160636e98405fbec8464a84b6464b32514db259e235eae0445346ffb7", "abcdefghi"},
	{"27635cf23fdf8a10f4cb2c52ade13038c38718c6d7ca716bfe726111a57ad201", "abcdefghij"},
	{"ae0d8e0e7c0336f0c3a72cefa4f24b625a6a460417a921d066058a0b81e23429", "Discard medicine more than two years old."},
	{"eeb56d02cf638f87ea8f11ebd5b0201afcece984d87be458578d3cfb51978f1b", "He who has a shady past knows that nice guys finish last."},
	{"dc640bf529608a381ea7065ecbcd0443b95f6e4c008de6e134aff1d36bd4b9d8", "I wouldn't marry him with a ten foot pole."},
	{"42e54375e60535eb07fc15c6350e10f2c22526f84db1d6f6bba925e154486f33", "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave"},
	{"4ed6aa9b88c84afbf928710b03714de69e2ad967c6a78586069adcb4c470d150", "The days of the digital watch are numbered.  -Tom Stoppard"},
	{"590c24d1877c1919fad12fe01a8796999e9d20cfbf9bc9bc72fa0bd69f0b04dd", "Nepal premier won't resign."},
	{"37d270687ee8ebafcd3c1a32f56e1e1304b3c93f252cb637d57a66d59c475eca", "For every action there is an equal and opposite government program."},
	{"306828fd89278838bb1c544c3032a1fd25ea65c40bba586437568828a5fbe944", "His money is twice tainted: 'taint yours and 'taint mine."},
	{"49965777eac71faf1e2fb0f6b239ba2fae770977940fd827bcbfe15def6ded53", "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977"},
	{"df99ee4e87dd3fb07922dee7735997bbae8f26db20c86137d4219fc4a37b77c3", "It's a tiny change to the code and not completely disgusting. - Bob Manchek"},
	{"920667c84a15b5ee3df4620169f5c0ec930cea0c580858e50e68848871ed65b4", "size:  a.out:  bad magic"},
	{"5e817fe20848a4a3932db68e90f8d54ec1b09603f0c99fdc051892b776acd462", "The major problem is with sendmail.  -Mark Horton"},
	{"6a9d47248ed38852f5f4b2e37e7dfad0ce8d1da86b280feef94ef267e468cff2", "Give me a rock, paper and scissors and I will move the world.  CCFestoon"},
	{"2e7aa1b362c94efdbff582a8bd3f7f61c8ce4c25bbde658ef1a7ae1010e2126f", "If the enemy is within range, then so are you."},
	{"e6729d51240b1e1da76d822fd0c55c75e409bcb525674af21acae1f11667c8ca", "It's well we cannot hear the screams/That we create in others' dreams."},
	{"09945e4d2743eb669f85e4097aa1cc39ea680a0b2ae2a65a42a5742b3b809610", "You remind me of a TV show, but that's all right: I watch it anyway."},
	{"1018d8b2870a974887c5174360f0fbaf27958eef15b24522a605c5dae4ae0845", "C is as portable as Stonehedge!!"},
	{"97c76b83c6645c78c261dcdc55d44af02d9f1df8057f997fd08c310c903624d5", "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley"},
	{"6bcbf25469e9544c5b5806b24220554fedb6695ba9b1510a76837414f7adb113", "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule"},
	{"1041988b06835481f0845be2a54f4628e1da26145b2de7ad1be3bb643cef9d4f", "How can you write a big system without C++?  -Paul Glick"},
}

func TestGolden(t *testing.T) {
	for i := 0; i < len(golden); i++ {
		g := golden[i]
		s := fmt.Sprintf("%x", Sum([]byte(g.in)))
		if s != g.out {
			t.Fatalf("Sum function: sha256d(%s) = %s want %s", g.in, s, g.out)
		}
		c := New()
		for j := 0; j < 3; j++ {
			if j < 2 {
				io.WriteString(c, g.in)
			} else {
				io.WriteString(c, g.in[0:len(g.in)/2])
				c.Sum(nil)
				io.WriteString(c, g.in[len(g.in)/2:])
			}
			s := fmt.Sprintf("%x", c.Sum(nil))
			if s != g.out {
				t.Fatalf("sha256[%d](%s) = %s want %s", j, g.in, s, g.out)
			}
			c.Reset()
		}
	}
}

func TestSize(t *testing.T) {
	c := New()
	if got := c.Size(); got != Size {
		t.Errorf("Size = %d; want %d", got, Size)
	}
}

func TestBlockSize(t *testing.T) {
	c := New()
	if got := c.BlockSize(); got != BlockSize {
		t.Errorf("BlockSize = %d want %d", got, BlockSize)
	}
}

// Tests that blockGeneric (pure Go) and block (in assembly for some architectures) match.
func TestBlockGeneric(t *testing.T) {
	gen, asm := New(), New()
	buf := make([]byte, BlockSize*20) // arbitrary factor
	rand.Read(buf)
	blockGeneric(gen, buf)
	block(asm, buf)
	if *gen != *asm {
		t.Error("block and blockGeneric resulted in different states")
	}
}

var bench = New()
var buf = make([]byte, 8192)

func benchmarkSize(b *testing.B, size int) {
	b.SetBytes(int64(size))
	sum := make([]byte, bench.Size())
	for i := 0; i < b.N; i++ {
		bench.Reset()
		bench.Write(buf[:size])
		bench.Sum(sum[:0])
	}
}

func BenchmarkHash8Bytes(b *testing.B) {
	benchmarkSize(b, 8)
}

func BenchmarkHash15Bytes(b *testing.B) {
	benchmarkSize(b, 15)
}

func BenchmarkHash64Bytes(b *testing.B) {
	benchmarkSize(b, 64)
}

func BenchmarkHash1K(b *testing.B) {
	benchmarkSize(b, 1024)
}

func BenchmarkHash8K(b *testing.B) {
	benchmarkSize(b, 8192)
}
