// Package request Golang spamc client
// Spamc - Golang spamc client
// Copyright (C) 2018 Andrew Colin Kissa <andrew@datopdog.io>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.
package request

import (
	"github.com/baruwa-enterprise/spamc/header"
)

const (
	Check Method = iota
	Headers
	Ping
	Process
	Report
	ReportIfSpam
	Skip
	Symbols
	Tell
)

const (
	NoAction TellAction = iota
	LearnAction
	ForgetAction
	ReportAction
	RevokeAction
)

const (
	NoneType MsgType = iota
	Ham
	Spam
)

// A Method represents a Spamc request method
type Method int

func (m Method) String() (s string) {
	n := [...]string{
		"CHECK",
		"HEADERS",
		"PING",
		"PROCESS",
		"REPORT",
		"REPORT_IFSPAM",
		"SKIP",
		"SYMBOLS",
		"TELL",
	}
	if m < Check || m > Tell {
		s = ""
		return
	}
	s = n[m]
	return
}

// UsesHeader checks if a method users a header
func (m Method) UsesHeader(h header.Header) (b bool) {
	switch m {
	case Check, Headers, Process, Report, ReportIfSpam, Symbols, Tell:
		if h == header.Compress || h == header.User {
			b = true
		}
		if h == header.ContentLength {
			b = true
		}
		if m == Tell {
			if h == header.Remove || h == header.Set || h == header.MessageClass {
				b = true
			}
		}
	}
	return
}

// A TellAction represents a Tell Action
// - Learn
// - Forget
// - Report
// - Revoke
type TellAction int

// A MsgType represents a Message type
// - Spam
// - Ham
type MsgType int

func (m MsgType) String() (s string) {
	n := [...]string{
		"",
		"ham",
		"spam",
	}
	if m < Ham || m > Spam {
		return
	}
	s = n[m]
	return
}
