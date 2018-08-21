// Copyright (C) 2018 Andrew Colin Kissa <andrew@datopdog.io>
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

/*
Package response Golang spamc client
Spamc - Golang spamc client
*/
package response

import (
	"testing"

	"github.com/baruwa-enterprise/spamc/request"
)

type StatusCodeTestKey struct {
	in     StatusCode
	out    string
	err    string
	istemp bool
}

var TestStatusCodes = []StatusCodeTestKey{
	{ExOK, "EX_OK", "Success", false},
	{ExUsage, "EX_USAGE", "Command line usage error", false},
	{ExDataErr, "EX_DATAERR", "Data format error", false},
	{ExNoInput, "EX_NOINPUT", "Cannot open input", false},
	{ExNpUser, "EX_NOUSER", "Addressee unknown", false},
	{ExNoHost, "EX_NOHOST", "Host name unknown", false},
	{ExUnAvailable, "EX_UNAVAILABLE", "Service unavailable", false},
	{ExSoftware, "EX_SOFTWARE", "Internal software error", false},
	{ExOSErr, "EX_OSERR", "System error", false},
	{ExOSFile, "EX_OSFILE", "Critical OS file missing", false},
	{ExCantCreat, "EX_CANTCREAT", "Can't create (user) output file", false},
	{ExIOErr, "EX_IOERR", "Input/output error", false},
	{ExTempFail, "EX_TEMPFAIL", "Temp failure; user is invited to retry", true},
	{ExProtocol, "EX_PROTOCOL", "Remote error in protocol", false},
	{ExNoPerm, "EX_NOPERM", "Permission denied", false},
	{ExConfig, "EX_CONFIG", "Configuration error", false},
	{ExTimeout, "EX_TIMEOUT", "Read timeout", true},
}

func TestStatusCode(t *testing.T) {
	for _, tt := range TestStatusCodes {
		if s := tt.in.String(); s != tt.out {
			t.Errorf("%q.String() = %q, want %q", tt.in, s, tt.out)
		}
		if s := tt.in.Error(); s != tt.err {
			t.Errorf("%q.Error() = %q, want %q", tt.in, s, tt.err)
		}
		if b := tt.in.IsTemp(); b != tt.istemp {
			t.Errorf("%q.IsTemp() = %t, want %t", tt.in, b, tt.istemp)
		}
	}
}

func TestNewResponse(t *testing.T) {
	r := NewResponse(request.Check)
	if r.RequestMethod != request.Check {
		t.Errorf("Got %q, want %q", r.RequestMethod, request.Check)
	}
}
