// Package header Golang spamc client
// Spamc - Golang spamc client
// Copyright (C) 2018 Andrew Colin Kissa <andrew@datopdog.io>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.
package header

const (
	// Compress represents the compress header
	Compress Header = iota
	User
	ContentLength
	MessageClass
	Remove
	Set
)

// A Header represents a spamc client header
type Header int

func (h Header) String() (s string) {
	names := [...]string{
		"Compress",
		"User",
		"Content-length",
		"Message-class",
		"Remove",
		"Set",
	}
	if h < Compress || h > Set {
		return
	}
	s = names[h]
	return
}
