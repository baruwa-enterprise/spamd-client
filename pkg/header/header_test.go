// Copyright (C) 2018-2021 Andrew Colin Kissa <andrew@datopdog.io>
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

/*
Package header Golang Spamd SpamAssassin Client
spamd-client - Golang Spamd SpamAssassin Client
*/
package header

import "testing"

type HeaderTestKey struct {
	in  Header
	out string
}

var NonExistant Header = 20

var TestHeaders = []HeaderTestKey{
	{Compress, "Compress"},
	{User, "User"},
	{ContentLength, "Content-length"},
	{MessageClass, "Message-class"},
	{Remove, "Remove"},
	{Set, "Set"},
	{NonExistant, ""},
}

func TestHeader(t *testing.T) {
	for _, tt := range TestHeaders {
		if s := tt.in.String(); s != tt.out {
			t.Errorf("%q.String() = %q, want %q", tt.in, s, tt.out)
		}
	}
}
