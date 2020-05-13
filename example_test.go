// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha256d_test

import (
	"fmt"
	"github.com/maxhero/sha256d"
)

func ExampleSum() {
	sum := sha256d.Sum([]byte("hello world\n"))
	fmt.Printf("%x", sum)
	// Output: f83e4b6bba3efac41f1ff56ee97adf7454680fee778924cb5ba06311d136ad1c
}

func ExampleNew() {
	h := sha256d.New()
	h.Write([]byte("hello world\n"))
	fmt.Printf("%x", h.Sum(nil))
	// Output: f83e4b6bba3efac41f1ff56ee97adf7454680fee778924cb5ba06311d136ad1c
}
