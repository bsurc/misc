// Copyright (c) 2018, Boise State University All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"io/ioutil"
	"strings"
)

// ReadOrPanic reads an entire file and returns a string trimmed of whitespace.
// Any error encountered is considered fatal.
func ReadOrPanic(path string) {
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err.Error())
	}
	return strings.TrimSpace(string(buf))
}
