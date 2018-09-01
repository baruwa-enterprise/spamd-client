// Copyright (C) 2018 Andrew Colin Kissa <andrew@datopdog.io>
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

/*
Package spamc Golang spamc client
Spamc - Golang spamc client
*/
package spamc

import (
	"bytes"
	"fmt"
	"go/build"
	"os"
	"path"
	"testing"
	"time"

	"github.com/baruwa-enterprise/spamc/request"
	"github.com/baruwa-enterprise/spamc/response"
)

var (
	gopath string
	mb     = []byte(`Date: Mon, 23 Jun 2015 11:40:36 -0400
From: Gopher <from@example.com>
To: Another Gopher <to@example.com>
Subject: Gophers at Gophercon
Message-Id: <v0421010eb70653b14e06@[192.168.1.84]>

Message body
James

My Workd

++++++++++++++
`)
)

type HeaderCheck struct {
	in  string
	out bool
}

func init() {
	gopath = os.Getenv("GOPATH")
	if gopath == "" {
		gopath = build.Default.GOPATH
	}
}

func TestBasics(t *testing.T) {
	// Test Non existent socket
	var expected string
	testsock := "/tmp/.dumx.sock"
	_, e := NewClient("unix", testsock, "exim", true)
	if e == nil {
		t.Fatalf("An error should be returned as sock does not exist")
	}
	expected = fmt.Sprintf(unixSockErr, testsock)
	if e.Error() != expected {
		t.Errorf("Expected %q want %q", expected, e)
	}
	// Test defaults
	_, e = NewClient("", "", "exim", true)
	if e == nil {
		t.Fatalf("An error should be returned as sock does not exist")
	}
	expected = fmt.Sprintf(unixSockErr, defaultSock)
	if e.Error() != expected {
		t.Errorf("Got %q want %q", expected, e)
	}
	// Test udp
	_, e = NewClient("udp", "127.1.1.1:4010", "exim", true)
	if e == nil {
		t.Fatalf("Expected an error got nil")
	}
	expected = "Protocol: udp is not supported"
	if e.Error() != expected {
		t.Errorf("Got %q want %q", expected, e)
	}
	// Test tcp
	network := "tcp"
	address := "127.1.1.1:4010"
	c, e := NewClient(network, address, "exim", true)
	if e != nil {
		t.Fatal("An error should not be returned")
	}
	if c.network != network {
		t.Errorf("Got %q want %q", c.network, network)
	}
	if c.address != address {
		t.Errorf("Got %q want %q", c.address, address)
	}
}

func TestSettings(t *testing.T) {
	network := "tcp"
	address := "127.1.1.1:4010"
	c, e := NewClient(network, address, "exim", true)
	if e != nil {
		t.Fatal("An error should not be returned")
	}
	// Test SetUser
	user := "Sa-Exim"
	if c.user != "exim" {
		t.Errorf("Got %q want %q", c.user, "exim")
	}
	c.SetUser(user)
	if c.user != user {
		t.Errorf("Got %q want %q", c.user, user)
	}
	// Test EnableCompression
	if !c.useCompression {
		t.Errorf("Got %t want %t", c.useCompression, true)
	}
	c.DisableCompression()
	if c.useCompression {
		t.Errorf("Got %t want %t", c.useCompression, false)
	}
	c.EnableCompression()
	if !c.useCompression {
		t.Errorf("Got %t want %t", c.useCompression, true)
	}
	// Test EnableTLS
	if c.useTLS {
		t.Errorf("Got %t want %t", c.useTLS, false)
	}
	c.EnableTLS()
	if !c.useTLS {
		t.Errorf("Got %t want %t", c.useTLS, true)
	}
	c.DisableTLS()
	if c.useTLS {
		t.Errorf("Got %t want %t", c.useTLS, false)
	}
	// Test EnableRawBody
	if c.returnRawBody {
		t.Errorf("Got %t want %t", c.returnRawBody, false)
	}
	c.EnableRawBody()
	if !c.returnRawBody {
		t.Errorf("Got %t want %t", c.returnRawBody, true)
	}
	c.DisableRawBody()
	if c.returnRawBody {
		t.Errorf("Got %t want %t", c.returnRawBody, false)
	}
	// Test SetRootCA
	if c.rootCA != "" {
		t.Errorf("Got %q want %q", c.rootCA, "")
	}
	fn := path.Join(gopath, "src/github.com/baruwa-enterprise/spamc/examples/ca.pem")
	e = c.SetRootCA(fn)
	if e == nil {
		t.Fatalf("Expected an error got nil")
	}
	if !os.IsNotExist(e) {
		t.Errorf("Expected os.IsNotExist error got: %s", e)
	}
	fn = path.Join(gopath, "src/github.com/baruwa-enterprise/spamc/examples/msg.txt")
	e = c.SetRootCA(fn)
	if e != nil {
		t.Fatalf("UnExpected error: %s", e)
	}
	if c.rootCA != fn {
		t.Errorf("Got %q want %q", c.rootCA, fn)
	}
	// Test EnableTLSVerification
	if c.insecureSkipVerify {
		t.Errorf("Got %t want %t", c.insecureSkipVerify, false)
	}
	c.DisableTLSVerification()
	if !c.insecureSkipVerify {
		t.Errorf("Got %t want %t", c.insecureSkipVerify, true)
	}
	c.EnableTLSVerification()
	if c.insecureSkipVerify {
		t.Errorf("Got %t want %t", c.insecureSkipVerify, false)
	}
	if c.connTimeout != defaultTimeout {
		t.Errorf("The default conn timeout should be set")
	}
	if c.connSleep != defaultSleep {
		t.Errorf("The default conn sleep should be set")
	}
	if c.connRetries != 0 {
		t.Errorf("The default conn retries should be set")
	}
	if c.cmdTimeout != defaultCmdTimeout {
		t.Errorf("The default cmdtimeout should be set")
	}
	expected := 2 * time.Second
	c.SetConnTimeout(expected)
	if c.connTimeout != expected {
		t.Errorf("Calling c.SetConnTimeout(%q) failed", expected)
	}
	c.SetCmdTimeout(expected)
	if c.cmdTimeout != expected {
		t.Errorf("Calling c.SetCmdTimeout(%q) failed", expected)
	}
	c.SetConnSleep(expected)
	if c.connSleep != expected {
		t.Errorf("Calling c.SetConnSleep(%q) failed", expected)
	}
	c.SetConnRetries(2)
	if c.connRetries != 2 {
		t.Errorf("Calling c.SetConnRetries(%q) failed", 2)
	}
	c.SetConnRetries(-2)
	if c.connRetries != 0 {
		t.Errorf("Preventing negative values in c.SetConnRetries(%q) failed", -2)
	}
}

func TestCheck(t *testing.T) {
	network := os.Getenv("SPAMD_NETWORK")
	address := os.Getenv("SPAMD_ADDRESS")
	user := os.Getenv("SPAMD_USER")
	if user == "" {
		user = "exim"
	}
	if network != "" && address != "" {
		th := []HeaderCheck{
			{"Content-Length", false},
			{"Spam", true},
		}
		c, e := NewClient(network, address, user, true)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		ir := bytes.NewReader(mb)
		r, e := c.Check(ir)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		if r.RequestMethod != request.Check {
			t.Errorf("Got %q want %q", r.RequestMethod, request.Check)
		}
		if r.StatusCode != response.ExOK {
			t.Errorf("Got %q want %q", r.StatusCode, response.ExOK)
		}
		if r.IsSpam {
			t.Errorf("Got %t want %t", r.IsSpam, false)
		}
		h := len(r.Headers)
		if h > 1 {
			t.Errorf("Got %d want %d", h, 1)
		}
		for _, hdr := range th {
			h := r.Headers.Get(hdr.in)
			if hdr.out {
				if h == "" {
					t.Errorf("Header: %s should be returned", hdr.in)
				}
			} else {
				if h != "" {
					t.Errorf("Header: %s should not be returned", hdr.in)
				}
			}
		}
		rlen := len(r.Raw)
		if rlen > 0 {
			t.Errorf("Got %d want %d", rlen, 0)
		}
		rlen = len(r.Rules)
		if rlen > 0 {
			t.Errorf("Got %d want %d", rlen, 0)
		}
		log(t, r)
	}
}

func TestHeaders(t *testing.T) {
	network := os.Getenv("SPAMD_NETWORK")
	address := os.Getenv("SPAMD_ADDRESS")
	user := os.Getenv("SPAMD_USER")
	if user == "" {
		user = "exim"
	}
	if network != "" && address != "" {
		th := []HeaderCheck{
			{"Content-Length", true},
			{"Spam", true},
		}
		c, e := NewClient(network, address, user, true)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		ir := bytes.NewReader(mb)
		r, e := c.Headers(ir)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		if r.RequestMethod != request.Headers {
			t.Errorf("Got %q want %q", r.RequestMethod, request.Headers)
		}
		if r.StatusCode != response.ExOK {
			t.Errorf("Got %q want %q", r.StatusCode, response.ExOK)
		}
		if r.IsSpam {
			t.Errorf("Got %t want %t", r.IsSpam, false)
		}
		h := len(r.Headers)
		if h < 2 || h > 2 {
			t.Errorf("Got %d want %d", h, 2)
		}
		for _, hdr := range th {
			h := r.Headers.Get(hdr.in)
			if hdr.out {
				if h == "" {
					t.Errorf("Header: %s should be returned", hdr.in)
				}
			} else {
				if h != "" {
					t.Errorf("Header: %s should not be returned", hdr.in)
				}
			}
		}
		rlen := len(r.Raw)
		if rlen > 0 {
			t.Errorf("Got %d want %d", rlen, 0)
		}
		rlen = len(r.Rules)
		if rlen > 0 {
			t.Errorf("Got %d want %d", rlen, 0)
		}
		log(t, r)
	}
}

func TestProcess(t *testing.T) {
	network := os.Getenv("SPAMD_NETWORK")
	address := os.Getenv("SPAMD_ADDRESS")
	user := os.Getenv("SPAMD_USER")
	if user == "" {
		user = "exim"
	}
	if network != "" && address != "" {
		th := []HeaderCheck{
			{"Content-Length", true},
			{"Spam", true},
		}
		c, e := NewClient(network, address, user, true)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		ir := bytes.NewReader(mb)
		r, e := c.Process(ir)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		if r.RequestMethod != request.Process {
			t.Errorf("Got %q want %q", r.RequestMethod, request.Process)
		}
		if r.StatusCode != response.ExOK {
			t.Errorf("Got %q want %q", r.StatusCode, response.ExOK)
		}
		if r.IsSpam {
			t.Errorf("Got %t want %t", r.IsSpam, false)
		}
		h := len(r.Headers)
		if h < 2 || h > 2 {
			t.Errorf("Got %d want %d", h, 2)
		}
		for _, hdr := range th {
			h := r.Headers.Get(hdr.in)
			if hdr.out {
				if h == "" {
					t.Errorf("Header: %s should be returned", hdr.in)
				}
			} else {
				if h != "" {
					t.Errorf("Header: %s should not be returned", hdr.in)
				}
			}
		}
		rlen := len(r.Raw)
		if rlen > 0 {
			t.Errorf("Got %d want %d", rlen, 0)
		}
		rlen = len(r.Rules)
		if rlen > 0 {
			t.Errorf("Got %d want %d", rlen, 0)
		}
		log(t, r)
	}
}

func TestReport(t *testing.T) {
	network := os.Getenv("SPAMD_NETWORK")
	address := os.Getenv("SPAMD_ADDRESS")
	user := os.Getenv("SPAMD_USER")
	if user == "" {
		user = "exim"
	}
	if network != "" && address != "" {
		th := []HeaderCheck{
			{"Content-Length", true},
			{"Spam", true},
		}
		c, e := NewClient(network, address, user, true)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		ir := bytes.NewReader(mb)
		r, e := c.Report(ir)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		if r.RequestMethod != request.Report {
			t.Errorf("Got %q want %q", r.RequestMethod, request.Report)
		}
		if r.StatusCode != response.ExOK {
			t.Errorf("Got %q want %q", r.StatusCode, response.ExOK)
		}
		if r.IsSpam {
			t.Errorf("Got %t want %t", r.IsSpam, false)
		}
		h := len(r.Headers)
		if h < 2 || h > 2 {
			t.Errorf("Got %d want %d", h, 2)
		}
		for _, hdr := range th {
			h := r.Headers.Get(hdr.in)
			if hdr.out {
				if h == "" {
					t.Errorf("Header: %s should be returned", hdr.in)
				}
			} else {
				if h != "" {
					t.Errorf("Header: %s should not be returned", hdr.in)
				}
			}
		}
		rlen := len(r.Raw)
		if rlen > 0 {
			t.Errorf("Got %d want %d", rlen, 0)
		}
		rlen = len(r.Rules)
		if rlen <= 0 {
			t.Errorf("Got %d want > %d", rlen, 0)
		}
		log(t, r)
	}
}

func TestReportIfSpam(t *testing.T) {
	network := os.Getenv("SPAMD_NETWORK")
	address := os.Getenv("SPAMD_ADDRESS")
	user := os.Getenv("SPAMD_USER")
	if user == "" {
		user = "exim"
	}
	if network != "" && address != "" {
		th := []HeaderCheck{
			{"Content-Length", true},
			{"Spam", true},
		}
		c, e := NewClient(network, address, user, true)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		ir := bytes.NewReader(mb)
		r, e := c.ReportIfSpam(ir)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		if r.RequestMethod != request.ReportIfSpam {
			t.Errorf("Got %q want %q", r.RequestMethod, request.ReportIfSpam)
		}
		if r.StatusCode != response.ExOK {
			t.Errorf("Got %q want %q", r.StatusCode, response.ExOK)
		}
		if r.IsSpam {
			t.Errorf("Got %t want %t", r.IsSpam, false)
		}
		h := len(r.Headers)
		if h < 2 || h > 2 {
			t.Errorf("Got %d want %d", h, 2)
		}
		for _, hdr := range th {
			h := r.Headers.Get(hdr.in)
			if hdr.out {
				if h == "" {
					t.Errorf("Header: %s should be returned", hdr.in)
				}
			} else {
				if h != "" {
					t.Errorf("Header: %s should not be returned", hdr.in)
				}
			}
		}
		rlen := len(r.Raw)
		if rlen > 0 {
			t.Errorf("Got %d want %d", rlen, 0)
		}
		rlen = len(r.Rules)
		if rlen > 0 {
			t.Errorf("Got %d want %d", rlen, 0)
		}
		log(t, r)
	}
}

func TestSymbols(t *testing.T) {
	network := os.Getenv("SPAMD_NETWORK")
	address := os.Getenv("SPAMD_ADDRESS")
	user := os.Getenv("SPAMD_USER")
	if user == "" {
		user = "exim"
	}
	if network != "" && address != "" {
		th := []HeaderCheck{
			{"Content-Length", true},
			{"Spam", true},
		}
		c, e := NewClient(network, address, user, true)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		ir := bytes.NewReader(mb)
		r, e := c.Symbols(ir)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		if r.RequestMethod != request.Symbols {
			t.Errorf("Got %q want %q", r.RequestMethod, request.Symbols)
		}
		if r.StatusCode != response.ExOK {
			t.Errorf("Got %q want %q", r.StatusCode, response.ExOK)
		}
		if r.IsSpam {
			t.Errorf("Got %t want %t", r.IsSpam, false)
		}
		h := len(r.Headers)
		if h < 2 || h > 2 {
			t.Errorf("Got %d want %d", h, 2)
		}
		for _, hdr := range th {
			h := r.Headers.Get(hdr.in)
			if hdr.out {
				if h == "" {
					t.Errorf("Header: %s should be returned", hdr.in)
				}
			} else {
				if h != "" {
					t.Errorf("Header: %s should not be returned", hdr.in)
				}
			}
		}
		rlen := len(r.Raw)
		if rlen > 0 {
			t.Errorf("Got %d want %d", rlen, 0)
		}
		rlen = len(r.Rules)
		if rlen == 0 {
			t.Errorf("Got %d want > %d", rlen, 0)
		}
		log(t, r)
	}
}

func TestTellHam(t *testing.T) {
	network := os.Getenv("SPAMD_NETWORK")
	address := os.Getenv("SPAMD_ADDRESS")
	user := os.Getenv("SPAMD_USER")
	if user == "" {
		user = "exim"
	}
	if network != "" && address != "" {
		th := []HeaderCheck{
			{"Content-Length", false},
			{"Spam", false},
		}
		c, e := NewClient(network, address, user, true)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		ir := bytes.NewReader(mb)
		r, e := c.Tell(ir, request.Ham, request.LearnAction)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		if r.RequestMethod != request.Tell {
			t.Errorf("Got %q want %q", r.RequestMethod, request.Tell)
		}
		if r.StatusCode != response.ExOK {
			t.Errorf("Got %q want %q", r.StatusCode, response.ExOK)
		}
		if r.IsSpam {
			t.Errorf("Got %t want %t", r.IsSpam, false)
		}
		h := len(r.Headers)
		if h > 1 {
			t.Errorf("Got %d want %d", h, 1)
		}
		for _, hdr := range th {
			h := r.Headers.Get(hdr.in)
			if hdr.out {
				if h == "" {
					t.Errorf("Header: %s should be returned", hdr.in)
				}
			} else {
				if h != "" {
					t.Errorf("Header: %s should not be returned", hdr.in)
				}
			}
		}
		rlen := len(r.Raw)
		if rlen > 0 {
			t.Errorf("Got %d want %d", rlen, 0)
		}
		rlen = len(r.Rules)
		if rlen > 0 {
			t.Errorf("Got %d want %d", rlen, 0)
		}
		log(t, r)
	}
}

func TestTellForgetHam(t *testing.T) {
	network := os.Getenv("SPAMD_NETWORK")
	address := os.Getenv("SPAMD_ADDRESS")
	user := os.Getenv("SPAMD_USER")
	if user == "" {
		user = "exim"
	}
	if network != "" && address != "" {
		th := []HeaderCheck{
			{"Content-Length", false},
			{"Spam", false},
			{"Didremove", true},
		}
		c, e := NewClient(network, address, user, true)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		ir := bytes.NewReader(mb)
		r, e := c.Tell(ir, request.Ham, request.ForgetAction)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		if r.RequestMethod != request.Tell {
			t.Errorf("Got %q want %q", r.RequestMethod, request.Tell)
		}
		if r.StatusCode != response.ExOK {
			t.Errorf("Got %q want %q", r.StatusCode, response.ExOK)
		}
		if r.IsSpam {
			t.Errorf("Got %t want %t", r.IsSpam, false)
		}
		h := len(r.Headers)
		if h > 1 {
			t.Errorf("Got %d want %d", h, 1)
		}
		for _, hdr := range th {
			h := r.Headers.Get(hdr.in)
			if hdr.out {
				if h == "" {
					t.Errorf("Header: %s should be returned", hdr.in)
				}
			} else {
				if h != "" {
					t.Errorf("Header: %s should not be returned", hdr.in)
				}
			}
		}
		rlen := len(r.Raw)
		if rlen > 0 {
			t.Errorf("Got %d want %d", rlen, 0)
		}
		rlen = len(r.Rules)
		if rlen > 0 {
			t.Errorf("Got %d want %d", rlen, 0)
		}
		log(t, r)
	}
}

func TestTellSpam(t *testing.T) {
	network := os.Getenv("SPAMD_NETWORK")
	address := os.Getenv("SPAMD_ADDRESS")
	user := os.Getenv("SPAMD_USER")
	if user == "" {
		user = "exim"
	}
	if network != "" && address != "" {
		th := []HeaderCheck{
			{"Content-Length", false},
			{"Spam", false},
			{"Didset", true},
		}
		c, e := NewClient(network, address, user, true)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		ir := bytes.NewReader(mb)
		r, e := c.Tell(ir, request.Spam, request.LearnAction)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		if r.RequestMethod != request.Tell {
			t.Errorf("Got %q want %q", r.RequestMethod, request.Tell)
		}
		if r.StatusCode != response.ExOK {
			t.Errorf("Got %q want %q", r.StatusCode, response.ExOK)
		}
		if r.IsSpam {
			t.Errorf("Got %t want %t", r.IsSpam, false)
		}
		h := len(r.Headers)
		if h > 1 {
			t.Errorf("Got %d want %d", h, 1)
		}
		for _, hdr := range th {
			h := r.Headers.Get(hdr.in)
			if hdr.out {
				if h == "" {
					t.Errorf("Header: %s should be returned", hdr.in)
				}
			} else {
				if h != "" {
					t.Errorf("Header: %s should not be returned", hdr.in)
				}
			}
		}
		rlen := len(r.Raw)
		if rlen > 0 {
			t.Errorf("Got %d want %d", rlen, 0)
		}
		rlen = len(r.Rules)
		if rlen > 0 {
			t.Errorf("Got %d want %d", rlen, 0)
		}
		log(t, r)
	}
}

func TestTellForgetSpam(t *testing.T) {
	network := os.Getenv("SPAMD_NETWORK")
	address := os.Getenv("SPAMD_ADDRESS")
	user := os.Getenv("SPAMD_USER")
	if user == "" {
		user = "exim"
	}
	if network != "" && address != "" {
		th := []HeaderCheck{
			{"Content-Length", false},
			{"Spam", false},
			{"Didremove", true},
		}
		c, e := NewClient(network, address, user, true)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		ir := bytes.NewReader(mb)
		r, e := c.Tell(ir, request.Spam, request.ForgetAction)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		if r.RequestMethod != request.Tell {
			t.Errorf("Got %q want %q", r.RequestMethod, request.Tell)
		}
		if r.StatusCode != response.ExOK {
			t.Errorf("Got %q want %q", r.StatusCode, response.ExOK)
		}
		if r.IsSpam {
			t.Errorf("Got %t want %t", r.IsSpam, false)
		}
		h := len(r.Headers)
		if h > 1 {
			t.Errorf("Got %d want %d", h, 1)
		}
		for _, hdr := range th {
			h := r.Headers.Get(hdr.in)
			if hdr.out {
				if h == "" {
					t.Errorf("Header: %s should be returned", hdr.in)
				}
			} else {
				if h != "" {
					t.Errorf("Header: %s should not be returned", hdr.in)
				}
			}
		}
		rlen := len(r.Raw)
		if rlen > 0 {
			t.Errorf("Got %d want %d", rlen, 0)
		}
		rlen = len(r.Rules)
		if rlen > 0 {
			t.Errorf("Got %d want %d", rlen, 0)
		}
		log(t, r)
	}
}

func log(t *testing.T, r *response.Response) {
	t.Logf("RequestMethod:\t%s\nStatusCode:\t%s\nStatusMsg:\t%s\nVersion:\t%s\nScore:\t%v\nBaseScore:\t%v\nIsSpam:\t%t\nHeaders:\t%v\nMsg:\t%v\nRules:\t%v",
		r.RequestMethod, r.StatusCode, r.StatusMsg, r.Version, r.Score, r.BaseScore, r.IsSpam, r.Headers, r.Msg, r.Rules)
}
