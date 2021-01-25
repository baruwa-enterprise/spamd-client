// Copyright (C) 2018-2021 Andrew Colin Kissa <andrew@datopdog.io>
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

/*
Package header Golang Spamd SpamAssassin Client
spamd-client - Golang Spamd SpamAssassin Client
*/
package header

const (
	// Compress represents the Compress header
	Compress Header = iota
	// User represents the User header
	User
	// ContentLength represents the Content-length header
	ContentLength
	// MessageClass represents the Message-Class header
	MessageClass
	// Remove represents the Remove header
	Remove
	// Set reprsents the Set header
	Set
)

// A Header represents a spamd-client header
type Header int

func (h Header) String() (s string) {
	n := [...]string{
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
	s = n[h]
	return
}
