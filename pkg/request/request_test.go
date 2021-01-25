// Copyright (C) 2018-2021 Andrew Colin Kissa <andrew@datopdog.io>
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

/*
Package request Golang Spamd SpamAssassin Client
spamd-client - Golang Spamd SpamAssassin Client
*/
package request

import (
	"testing"

	"github.com/baruwa-enterprise/spamd-client/pkg/header"
)

type MethodTestKey struct {
	in  Method
	out string
}

type UsesHeaderTestKey struct {
	in     Method
	header header.Header
	out    bool
}

type MsgTypeTestKey struct {
	in  MsgType
	out string
}

var (
	NonExistantMethod  Method  = 20
	NonExistantMsgType MsgType = 20
)

var TestMethods = []MethodTestKey{
	{Check, "CHECK"},
	{Headers, "HEADERS"},
	{Ping, "PING"},
	{Process, "PROCESS"},
	{Report, "REPORT"},
	{ReportIfSpam, "REPORT_IFSPAM"},
	{Skip, "SKIP"},
	{Symbols, "SYMBOLS"},
	{Tell, "TELL"},
	{NonExistantMethod, ""},
}

var TestUsesHeaders = []UsesHeaderTestKey{
	{Check, header.Compress, true},
	{Check, header.User, true},
	{Check, header.ContentLength, true},
	{Check, header.Remove, false},
	{Check, header.Set, false},
	{Check, header.MessageClass, false},
	{Skip, header.MessageClass, false},
	{Tell, header.Compress, true},
	{Tell, header.User, true},
	{Tell, header.ContentLength, true},
	{Tell, header.Remove, true},
	{Tell, header.Set, true},
	{Tell, header.MessageClass, true},
}

var TestMsgTypes = []MsgTypeTestKey{
	{NoneType, ""},
	{Ham, "ham"},
	{Spam, "spam"},
	{NonExistantMsgType, ""},
}

func TestMethod(t *testing.T) {
	for _, tt := range TestMethods {
		if s := tt.in.String(); s != tt.out {
			t.Errorf("%q.String() = %q, want %q", tt.in, s, tt.out)
		}
	}
}

func TestUsesHeader(t *testing.T) {
	for _, tt := range TestUsesHeaders {
		if b := tt.in.UsesHeader(tt.header); b != tt.out {
			t.Errorf("%q.UsesHeader(%q) = %t, want %t", tt.in, tt.header, b, tt.out)
		}
	}
}

func TestMsgType(t *testing.T) {
	for _, tt := range TestMsgTypes {
		if s := tt.in.String(); s != tt.out {
			t.Errorf("%q.String() = %q, want %q", tt.in, s, tt.out)
		}
	}
}
