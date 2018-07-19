// Package response Golang spamc client
// Spamc - Golang spamc client
// Copyright (C) 2018 Andrew Colin Kissa <andrew@datopdog.io>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.
package response

import (
	"net/textproto"

	"github.com/baruwa-enterprise/spamc/request"
)

const (
	// ExOK => EX_OK
	ExOK StatusCode = 0
	// ExUsage => EX_USAGE
	ExUsage StatusCode = iota + 64
	// ExDataErr => EX_DATAERR
	ExDataErr
	// ExNoInput => EX_NOINPUT
	ExNoInput
	// ExNpUser => EX_NOUSER
	ExNpUser
	// ExNoHost => EX_NOHOST
	ExNoHost
	// ExUnAvailable => EX_UNAVAILABLE
	ExUnAvailable
	// ExSoftware => EX_SOFTWARE
	ExSoftware
	// ExOSErr => EX_OSERR
	ExOSErr
	// ExOSFile => EX_OSFILE
	ExOSFile
	// ExCantCreat => EX_CANTCREAT
	ExCantCreat
	// ExIOErr => EX_IOERR
	ExIOErr
	// ExTempFail => EX_TEMPFAIL
	ExTempFail
	// ExProtocol => EX_PROTOCOL
	ExProtocol
	// ExNoPerm => EX_NOPERM
	ExNoPerm
	// ExConfig => EX_CONFIG
	ExConfig
	// ExTimeout => EX_TIMEOUT
	ExTimeout
)

var (
	// StatusCodes maps status code string to StatusCode
	StatusCodes = map[string]StatusCode{
		"EX_OK":          ExOK,
		"EX_USAGE":       ExUsage,
		"EX_DATAERR":     ExDataErr,
		"EX_NOINPUT":     ExNoInput,
		"EX_NOUSER":      ExNpUser,
		"EX_NOHOST":      ExNoHost,
		"EX_UNAVAILABLE": ExUnAvailable,
		"EX_SOFTWARE":    ExSoftware,
		"EX_OSERR":       ExOSErr,
		"EX_OSFILE":      ExOSFile,
		"EX_CANTCREAT":   ExCantCreat,
		"EX_IOERR":       ExIOErr,
		"EX_TEMPFAIL":    ExTempFail,
		"EX_PROTOCOL":    ExProtocol,
		"EX_NOPERM":      ExNoPerm,
		"EX_CONFIG":      ExConfig,
		"EX_TIMEOUT":     ExTimeout,
	}
)

// A StatusCode represents a SpamD server status code.
type StatusCode int

func (s StatusCode) String() (r string) {
	m := map[StatusCode]string{
		ExOK:          "EX_OK",
		ExUsage:       "EX_USAGE",
		ExDataErr:     "EX_DATAERR",
		ExNoInput:     "EX_NOINPUT",
		ExNpUser:      "EX_NOUSER",
		ExNoHost:      "EX_NOHOST",
		ExUnAvailable: "EX_UNAVAILABLE",
		ExSoftware:    "EX_SOFTWARE",
		ExOSErr:       "EX_OSERR",
		ExOSFile:      "EX_OSFILE",
		ExCantCreat:   "EX_CANTCREAT",
		ExIOErr:       "EX_IOERR",
		ExTempFail:    "EX_TEMPFAIL",
		ExProtocol:    "EX_PROTOCOL",
		ExNoPerm:      "EX_NOPERM",
		ExConfig:      "EX_CONFIG",
		ExTimeout:     "EX_TIMEOUT",
	}
	r = m[s]
	return
}

func (s StatusCode) Error() (r string) {
	m := map[StatusCode]string{
		ExOK:          "Success",
		ExUsage:       "Command line usage error",
		ExDataErr:     "Data format error",
		ExNoInput:     "Cannot open input",
		ExNpUser:      "Addressee unknown",
		ExNoHost:      "Host name unknown",
		ExUnAvailable: "Service unavailable",
		ExSoftware:    "Internal software error",
		ExOSErr:       "System error",
		ExOSFile:      "Critical OS file missing",
		ExCantCreat:   "Can't create (user) output file",
		ExIOErr:       "Input/output error",
		ExTempFail:    "Temp failure; user is invited to retry",
		ExProtocol:    "Remote error in protocol",
		ExNoPerm:      "Permission denied",
		ExConfig:      "Configuration error",
		ExTimeout:     "Read timeout",
	}
	r = m[s]
	return
}

// IsTemp returns a bool indicating if the status is temporary.
func (s StatusCode) IsTemp() (r bool) {
	switch s {
	case ExTempFail, ExTimeout:
		r = true
	}
	return
}

// A Response represents a server response from a Spamc server.
type Response struct {
	RequestMethod request.Method
	StatusCode    StatusCode
	StatusMsg     string
	Version       string
	Score         float64
	BaseScore     float64
	IsSpam        bool
	Headers       textproto.MIMEHeader
	Msg           *Msg
	Raw           []byte
	Rules         []map[string]string
}

// NewResponse returns a new Response
func NewResponse(m request.Method) *Response {
	return &Response{
		RequestMethod: m,
		Headers:       make(textproto.MIMEHeader),
		Msg:           NewMsg(),
		Rules:         make([]map[string]string, 1),
		Raw:           make([]byte, 1),
	}
}

// A Msg represents a message response from a Spamc server.
type Msg struct {
	Header textproto.MIMEHeader
	Body   []byte
}

// NewMsg returns a new Msg
func NewMsg() *Msg {
	return &Msg{
		Header: make(textproto.MIMEHeader),
		Body:   make([]byte, 1),
	}
}
