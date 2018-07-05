// Package request Golang spamc client
// Spamc - Golang spamc client
// Copyright (C) 2018 Andrew Colin Kissa <andrew@datopdog.io>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.
package request

import (
	"fmt"
	"net/textproto"
	"strconv"

	"github.com/baruwa-enterprise/spamc/header"
)

const (
	ClientVersion = "1.5"
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

var (
	methods = []Method{
		Check,
		Headers,
		Ping,
		Process,
		Report,
		ReportIfSpam,
		Skip,
		Symbols,
		Tell,
	}
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
		if m == Tell && h == header.Remove || h == header.Set || h == header.MessageClass {
			b = true
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

// A Request represents a client request to a Spamc server.
type Request struct {
	Method    Method
	Headers   textproto.MIMEHeader
	Body      []byte
	Action    TellAction
	LearnType MsgType
}

// SetHeader sets the request header
func (r *Request) SetHeader(h header.Header, v string) {
	if r.Method.UsesHeader(h) {
		r.Headers.Set(h.String(), v)
	}
}

// SetLearnType sets the learn type
func (r *Request) SetLearnType(t MsgType) (err error) {
	if t == NoneType {
		err = fmt.Errorf("Set the correct learn type")
		return
	}
	r.LearnType = t
	return
}

// SetAction sets the action
func (r *Request) SetAction(a TellAction) (err error) {
	switch r.Method {
	case Tell:
		if r.LearnType == NoneType {
			err = fmt.Errorf("Call SetLearnType() before calling SetAction")
			return
		}
		r.Action = a
	default:
		err = fmt.Errorf("Method: %s does not support actions", r.Method)
		return
	}
	// Set the headers
	switch r.Action {
	case LearnAction:
		r.SetHeader(header.MessageClass, r.LearnType.String())
		r.SetHeader(header.Set, "local")
	case ForgetAction:
		r.SetHeader(header.Remove, "local")
	case ReportAction:
		r.SetHeader(header.MessageClass, Spam.String())
		r.SetHeader(header.Set, "local, remote")
	case RevokeAction:
		r.SetHeader(header.MessageClass, Ham.String())
		r.SetHeader(header.Remove, "remote")
		r.SetHeader(header.Set, "local")
	}
	return
}

// Request returns the request line
func (r *Request) Request() (rs string) {
	return fmt.Sprintf("%s SPAMC/%s", r.Method, ClientVersion)
}

// NewRequest creates and returns a new Request
func NewRequest(m Method, b []byte, u string, c bool) (r *Request, err error) {
	r = &Request{
		Method:  m,
		Headers: make(textproto.MIMEHeader),
		Body:    b,
	}
	if u != "" && m.UsesHeader(header.User) {
		r.Headers.Set(header.User.String(), u)
	}
	if c && m.UsesHeader(header.Compress) {
		r.Headers.Set(header.Compress.String(), "1")
	}
	if b != nil && len(b) > 0 {
		r.Headers.Set(header.ContentLength.String(), strconv.Itoa(len(b)+2))
	}
	return
}
