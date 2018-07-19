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
	// Check represents the CHECK Method
	Check Method = iota
	// Headers represents the HEADERS Method
	Headers
	// Ping represents the PING Method
	Ping
	// Process represents the PROCESS Method
	Process
	// Report represents the REPORT Method
	Report
	// ReportIfSpam represents the REPORT_IFSPAM Method
	ReportIfSpam
	// Skip represents the SKIP Method
	Skip
	// Symbols represents the SYMBOLS Method
	Symbols
	// Tell represents the TELL Method
	Tell
)

const (
	// NoAction is NOOP action
	NoAction TellAction = iota
	// LearnAction is LEARN action
	LearnAction
	// ForgetAction is FORGET action
	ForgetAction
	// ReportAction is REPORT action
	ReportAction
	// RevokeAction is REVOKE action
	RevokeAction
)

const (
	// NoneType is non type msg
	NoneType MsgType = iota
	// Ham is a ham msg type
	Ham
	// Spam is a spam msg typ
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
