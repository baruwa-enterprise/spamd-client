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
	"compress/bzip2"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/baruwa-enterprise/spamc/request"
	"github.com/baruwa-enterprise/spamc/response"
)

const (
	StringTest = iota + 1
	BytesTest
	BufferTest
	FileTest
)

var (
	tlsRootCA, network, address, user, useTLS string
	ioTests                                   = []int{
		StringTest,
		BytesTest,
		BufferTest,
		FileTest,
	}
)

type HeaderCheck struct {
	in  string
	out bool
}

func init() {
	tlsp := os.Getenv("SPAMD_TLS_CA")
	if tlsp != "" {
		tlsRootCA = tlsp
	} else {
		tlsRootCA = "./examples/data/ca-chain.cert.pem"
	}
	network = os.Getenv("SPAMD_NETWORK")
	address = os.Getenv("SPAMD_ADDRESS")
	user = os.Getenv("SPAMD_USER")
	useTLS = os.Getenv("SPAMD_USE_TLS")
	if user == "" {
		user = "exim"
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
	netwk := "tcp"
	addr := "127.1.1.1:4010"
	c, e := NewClient(netwk, addr, "exim", true)
	if e != nil {
		t.Fatal("An error should not be returned")
	}
	if c.network != netwk {
		t.Errorf("Got %q want %q", c.network, netwk)
	}
	if c.address != addr {
		t.Errorf("Got %q want %q", c.address, addr)
	}
}

func TestSettings(t *testing.T) {
	netwk := "tcp"
	addr := "127.1.1.1:4010"
	c, e := NewClient(netwk, addr, "exim", true)
	if e != nil {
		t.Fatal("An error should not be returned")
	}
	// ConnTimeout
	if c.connTimeout != defaultTimeout {
		t.Errorf("The default conn timeout should be set")
	}
	expected := 2 * time.Second
	c.SetConnTimeout(expected)
	if c.connTimeout != expected {
		t.Errorf("Calling c.SetConnTimeout(%q) failed", expected)
	}
	// ConnSleep
	if c.connSleep != defaultSleep {
		t.Errorf("The default conn sleep should be set")
	}
	c.SetConnSleep(expected)
	if c.connSleep != expected {
		t.Errorf("Calling c.SetConnSleep(%q) failed", expected)
	}
	// ConnRetries
	if c.connRetries != 0 {
		t.Errorf("The default conn retries should be set")
	}
	c.SetConnRetries(2)
	if c.connRetries != 2 {
		t.Errorf("Calling c.SetConnRetries(%q) failed", 2)
	}
	c.SetConnRetries(-2)
	if c.connRetries != 0 {
		t.Errorf("Preventing negative values in c.SetConnRetries(%q) failed", -2)
	}
	// CmdTimeout
	if c.cmdTimeout != defaultCmdTimeout {
		t.Errorf("The default cmdtimeout should be set")
	}
	c.SetCmdTimeout(expected)
	if c.cmdTimeout != expected {
		t.Errorf("Calling c.SetCmdTimeout(%q) failed", expected)
	}
}

func TestUser(t *testing.T) {
	netwk := "tcp"
	addr := "127.1.1.1:4010"
	c, e := NewClient(netwk, addr, "exim", true)
	if e != nil {
		t.Fatal("An error should not be returned")
	}
	// Test SetUser
	usr := "Sa-Exim"
	if c.user != "exim" {
		t.Errorf("Got %q want %q", c.user, "exim")
	}
	c.SetUser(usr)
	if c.user != usr {
		t.Errorf("Got %q want %q", c.user, usr)
	}
}

func TestCompression(t *testing.T) {
	netwk := "tcp"
	addr := "127.1.1.1:4010"
	c, e := NewClient(netwk, addr, "exim", true)
	if e != nil {
		t.Fatal("An error should not be returned")
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
}

func TestTLS(t *testing.T) {
	netwk := "tcp"
	addr := "127.1.1.1:4010"
	c, e := NewClient(netwk, addr, "exim", true)
	if e != nil {
		t.Fatal("An error should not be returned")
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
}

func TestRaw(t *testing.T) {
	netwk := "tcp"
	addr := "127.1.1.1:4010"
	c, e := NewClient(netwk, addr, "exim", true)
	if e != nil {
		t.Fatal("An error should not be returned")
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
}

func TestRootCA(t *testing.T) {
	netwk := "tcp"
	addr := "127.1.1.1:4010"
	c, e := NewClient(netwk, addr, "exim", true)
	if e != nil {
		t.Fatal("An error should not be returned")
	}
	// Test SetRootCA
	if c.rootCA != "" {
		t.Errorf("Got %q want %q", c.rootCA, "")
	}
	fn := "./examples/ca.pem"
	e = c.SetRootCA(fn)
	if e == nil {
		t.Fatalf("Expected an error got nil")
	}
	if !os.IsNotExist(e) {
		t.Errorf("Expected os.IsNotExist error got: %s", e)
	}
	fn = "./examples/data/ham.txt"
	e = c.SetRootCA(fn)
	if e != nil {
		t.Fatalf("UnExpected error: %s", e)
	}
	if c.rootCA != fn {
		t.Errorf("Got %q want %q", c.rootCA, fn)
	}
}

func TestTLSVerification(t *testing.T) {
	netwk := "tcp"
	addr := "127.1.1.1:4010"
	c, e := NewClient(netwk, addr, "exim", true)
	if e != nil {
		t.Fatal("An error should not be returned")
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
}

func TestPing(t *testing.T) {
	if network != "" && address != "" {
		c, e := NewClient(network, address, user, true)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		if useTLS == "1" {
			c.SetRootCA(tlsRootCA)
			c.EnableTLS()
			c.EnableTLSVerification()
		}
		s, e := c.Ping()
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		if !s {
			t.Error("Ping failed")
		}
	} else {
		t.Skip("skipping test; $SPAMD_NETWORK or $SPAMD_ADDRESS not set")
	}
}

func TestIOReader(t *testing.T) {
	if network != "" && address != "" {
		c, e := NewClient(network, address, user, true)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		fn := "./examples/data/spam.tar.bz2"
		var ir io.Reader
		f, e := os.Open(fn)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		defer f.Close()
		ir = bzip2.NewReader(f)
		_, e = c.Check(ir)
		if e == nil {
			t.Fatal("An error should be returned")
		}
		if e.Error() != noSizeErr {
			t.Errorf("Got %s want %s", e, noSizeErr)
		}
	} else {
		t.Skip("skipping test; $SPAMD_NETWORK or $SPAMD_ADDRESS not set")
	}
}

func TestCheck(t *testing.T) {
	if network != "" && address != "" {
		th := []HeaderCheck{
			{"Content-Length", false},
			{"Spam", true},
		}
		c, e := NewClient(network, address, user, true)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		if useTLS == "1" {
			c.SetRootCA(tlsRootCA)
			c.EnableTLS()
			c.EnableTLSVerification()
		}
		check(t, c, th, 1, 0, 0, false)
		check(t, c, th, 1, 0, 0, true)
		if useTLS != "1" {
			c.DisableCompression()
			check(t, c, th, 1, 0, 0, false)
			check(t, c, th, 1, 0, 0, true)
		}
	} else {
		t.Skip("skipping test; $SPAMD_NETWORK or $SPAMD_ADDRESS not set")
	}
}

func check(t *testing.T, c *Client, th []HeaderCheck, hlen, rawlen, ruleslen int, isspam bool) {
	var ir io.Reader
	f, e := getFile(isspam)
	if e != nil {
		t.Fatalf("Unexpected error: %s", e)
	}
	defer f.Close()
	for _, testtype := range ioTests {
		f.Seek(0, 0)
		ir, e = getReader(f, testtype)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		//
		r, e := c.Check(ir)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		basicChecks(t, r, request.Check, th, hlen, isspam)
		rlen := len(r.Raw)
		if rlen > rawlen {
			t.Errorf("Got %d want %d", rlen, rawlen)
		}
		rlen = len(r.Rules)
		if rlen > ruleslen {
			t.Errorf("Got %d want %d", rlen, ruleslen)
		}
		log(t, r)
	}
}

func TestHeaders(t *testing.T) {
	if network != "" && address != "" {
		th := []HeaderCheck{
			{"Content-Length", true},
			{"Spam", true},
		}
		c, e := NewClient(network, address, user, true)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		if useTLS == "1" {
			c.SetRootCA(tlsRootCA)
			c.EnableTLS()
			c.EnableTLSVerification()
		}
		headers(t, c, th, 2, 0, 0, false, true)
		headers(t, c, th, 2, 0, 0, true, false)
	} else {
		t.Skip("skipping test; $SPAMD_NETWORK or $SPAMD_ADDRESS not set")
	}
}

func headers(t *testing.T, c *Client, th []HeaderCheck, hlen, rawlen, ruleslen int, isspam, rawbody bool) {
	var ir io.Reader
	f, e := getFile(isspam)
	if e != nil {
		t.Fatalf("Unexpected error: %s", e)
	}
	defer f.Close()
	for _, testtype := range ioTests {
		f.Seek(0, 0)
		ir, e = getReader(f, testtype)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		//
		if rawbody {
			c.EnableRawBody()
		} else {
			c.DisableRawBody()
		}
		r, e := c.Headers(ir)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		basicChecks(t, r, request.Headers, th, hlen, isspam)
		rlen := len(r.Raw)
		if rawbody {
			if rlen <= rawlen {
				t.Errorf("Got %d want > %d", rlen, rawlen)
			}
		} else {
			if rlen > rawlen {
				t.Errorf("Got %d want %d", rlen, rawlen)
			}
		}
		rlen = len(r.Rules)
		if rlen > ruleslen {
			t.Errorf("Got %d want %d", rlen, ruleslen)
		}
		log(t, r)
	}
}

func TestProcess(t *testing.T) {
	if network != "" && address != "" {
		th := []HeaderCheck{
			{"Content-Length", true},
			{"Spam", true},
		}
		c, e := NewClient(network, address, user, true)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		if useTLS == "1" {
			c.SetRootCA(tlsRootCA)
			c.EnableTLS()
			c.EnableTLSVerification()
		}
		process(t, c, th, 2, 0, 0, false)
		process(t, c, th, 2, 0, 0, true)
	} else {
		t.Skip("skipping test; $SPAMD_NETWORK or $SPAMD_ADDRESS not set")
	}
}

func process(t *testing.T, c *Client, th []HeaderCheck, hlen, rawlen, ruleslen int, isspam bool) {
	var ir io.Reader
	f, e := getFile(isspam)
	if e != nil {
		t.Fatalf("Unexpected error: %s", e)
	}
	defer f.Close()
	for _, testtype := range ioTests {
		f.Seek(0, 0)
		ir, e = getReader(f, testtype)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		//
		r, e := c.Process(ir)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		basicChecks(t, r, request.Process, th, hlen, isspam)
		rlen := len(r.Raw)
		if rlen > rawlen {
			t.Errorf("Got %d want %d", rlen, rawlen)
		}
		rlen = len(r.Rules)
		if isspam {
			if rlen <= ruleslen {
				t.Errorf("Got %d want > %d", rlen, ruleslen)
			}
		} else {
			if rlen > ruleslen {
				t.Errorf("Got %d want %d", rlen, ruleslen)
			}
		}
		log(t, r)
	}
}

func TestReport(t *testing.T) {
	if network != "" && address != "" {
		th := []HeaderCheck{
			{"Content-Length", true},
			{"Spam", true},
		}
		c, e := NewClient(network, address, user, true)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		if useTLS == "1" {
			c.SetRootCA(tlsRootCA)
			c.EnableTLS()
			c.EnableTLSVerification()
		}
		report(t, c, th, 2, 0, 0, false, true)
		report(t, c, th, 2, 0, 0, true, false)
	} else {
		t.Skip("skipping test; $SPAMD_NETWORK or $SPAMD_ADDRESS not set")
	}
}

func report(t *testing.T, c *Client, th []HeaderCheck, hlen, rawlen, ruleslen int, isspam, rawbody bool) {
	ir, e := getFile(isspam)
	if e != nil {
		t.Fatalf("Unexpected error: %s", e)
	}
	defer ir.Close()
	if rawbody {
		c.EnableRawBody()
	} else {
		c.DisableRawBody()
	}
	r, e := c.Report(ir)
	if e != nil {
		t.Fatalf("Unexpected error: %s", e)
	}
	basicChecks(t, r, request.Report, th, hlen, isspam)
	rlen := len(r.Raw)
	if rawbody {
		if rlen <= rawlen {
			t.Errorf("Got %d want > %d", rlen, rawlen)
		}
	} else {
		if rlen > rawlen {
			t.Errorf("Got %d want %d", rlen, rawlen)
		}
	}
	rlen = len(r.Rules)
	if rlen <= ruleslen {
		t.Errorf("Got %d want > %d", rlen, ruleslen)
	}
	log(t, r)
}

func TestReportIfSpam(t *testing.T) {
	if network != "" && address != "" {
		th := []HeaderCheck{
			{"Content-Length", true},
			{"Spam", true},
		}
		c, e := NewClient(network, address, user, true)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		if useTLS == "1" {
			c.SetRootCA(tlsRootCA)
			c.EnableTLS()
			c.EnableTLSVerification()
		}
		reportifspam(t, c, th, 2, 0, 0, false)
		reportifspam(t, c, th, 2, 0, 0, true)
	} else {
		t.Skip("skipping test; $SPAMD_NETWORK or $SPAMD_ADDRESS not set")
	}
}

func reportifspam(t *testing.T, c *Client, th []HeaderCheck, hlen, rawlen, ruleslen int, isspam bool) {
	ir, e := getFile(isspam)
	if e != nil {
		t.Fatalf("Unexpected error: %s", e)
	}
	defer ir.Close()
	r, e := c.ReportIfSpam(ir)
	if e != nil {
		t.Fatalf("Unexpected error: %s", e)
	}
	basicChecks(t, r, request.ReportIfSpam, th, hlen, isspam)
	rlen := len(r.Raw)
	if rlen > rawlen {
		t.Errorf("Got %d want %d", rlen, rawlen)
	}
	rlen = len(r.Rules)
	if isspam {
		if rlen <= ruleslen {
			t.Errorf("Got %d want > %d", rlen, ruleslen)
		}
	} else {
		if rlen > ruleslen {
			t.Errorf("Got %d want %d", rlen, ruleslen)
		}
	}
	log(t, r)
}

func TestSymbols(t *testing.T) {
	if network != "" && address != "" {
		th := []HeaderCheck{
			{"Content-Length", true},
			{"Spam", true},
		}
		c, e := NewClient(network, address, user, true)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		if useTLS == "1" {
			c.SetRootCA(tlsRootCA)
			c.EnableTLS()
			c.EnableTLSVerification()
		}
		symbols(t, c, th, 2, 0, 0, false, true)
		symbols(t, c, th, 2, 0, 0, true, false)
	} else {
		t.Skip("skipping test; $SPAMD_NETWORK or $SPAMD_ADDRESS not set")
	}
}

func symbols(t *testing.T, c *Client, th []HeaderCheck, hlen, rawlen, ruleslen int, isspam, rawbody bool) {
	var ir io.Reader
	f, e := getFile(isspam)
	if e != nil {
		t.Fatalf("Unexpected error: %s", e)
	}
	defer f.Close()
	for _, testtype := range ioTests {
		f.Seek(0, 0)
		ir, e = getReader(f, testtype)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		//
		if rawbody {
			c.EnableRawBody()
		} else {
			c.DisableRawBody()
		}
		r, e := c.Symbols(ir)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		basicChecks(t, r, request.Symbols, th, hlen, isspam)
		rlen := len(r.Raw)
		if rawbody {
			if rlen <= rawlen {
				t.Errorf("Got %d want > %d", rlen, 0)
			}
		} else {
			if rlen > rawlen {
				t.Errorf("Got %d want %d", rlen, 0)
			}
		}
		rlen = len(r.Rules)
		if rlen == ruleslen {
			t.Errorf("Got %d want > %d", rlen, ruleslen)
		}
		log(t, r)
	}
}

func TestTellError(t *testing.T) {
	if network != "" && address != "" {
		c, e := NewClient(network, address, user, true)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		ir, e := getFile(false)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		defer ir.Close()
		_, e = c.Tell(ir, request.MsgType(100), request.LearnAction)
		if e == nil {
			t.Fatalf("An error should be returned")
		}
		if e.Error() != invalidLearnTypeErr {
			t.Errorf("Got %s want %s", e, invalidLearnTypeErr)
		}
	} else {
		t.Skip("skipping test; $SPAMD_NETWORK or $SPAMD_ADDRESS not set")
	}
}

func TestTellHam(t *testing.T) {
	if network != "" && address != "" {
		th := []HeaderCheck{
			{"Content-Length", false},
			{"Spam", false},
		}
		c, e := NewClient(network, address, user, true)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		if useTLS == "1" {
			c.SetRootCA(tlsRootCA)
			c.EnableTLS()
			c.EnableTLSVerification()
		}
		tell(t, c, request.Ham, request.LearnAction, th, 1, 0, 0, false)
	} else {
		t.Skip("skipping test; $SPAMD_NETWORK or $SPAMD_ADDRESS not set")
	}
}

func TestTellForgetHam(t *testing.T) {
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
		if useTLS == "1" {
			c.SetRootCA(tlsRootCA)
			c.EnableTLS()
			c.EnableTLSVerification()
		}
		tell(t, c, request.Ham, request.ForgetAction, th, 1, 0, 0, false)
	} else {
		t.Skip("skipping test; $SPAMD_NETWORK or $SPAMD_ADDRESS not set")
	}
}

func TestTellSpam(t *testing.T) {
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
		if useTLS == "1" {
			c.SetRootCA(tlsRootCA)
			c.EnableTLS()
			c.EnableTLSVerification()
		}
		tell(t, c, request.Spam, request.LearnAction, th, 1, 0, 0, false)
	} else {
		t.Skip("skipping test; $SPAMD_NETWORK or $SPAMD_ADDRESS not set")
	}
}

func TestTellForgetSpam(t *testing.T) {
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
		if useTLS == "1" {
			c.SetRootCA(tlsRootCA)
			c.EnableTLS()
			c.EnableTLSVerification()
		}
		tell(t, c, request.Spam, request.ForgetAction, th, 1, 0, 0, false)
	} else {
		t.Skip("skipping test; $SPAMD_NETWORK or $SPAMD_ADDRESS not set")
	}
}

func TestLearnHam(t *testing.T) {
	if network != "" && address != "" {
		th := []HeaderCheck{
			{"Content-Length", false},
			{"Spam", false},
		}
		c, e := NewClient(network, address, user, true)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		if useTLS == "1" {
			c.SetRootCA(tlsRootCA)
			c.EnableTLS()
			c.EnableTLSVerification()
		}
		learn(t, c, request.Ham, th, 1, 0, 0, false)
	} else {
		t.Skip("skipping test; $SPAMD_NETWORK or $SPAMD_ADDRESS not set")
	}
}

func TestLearnSpam(t *testing.T) {
	if network != "" && address != "" {
		th := []HeaderCheck{
			{"Content-Length", false},
			{"Spam", false},
		}
		c, e := NewClient(network, address, user, true)
		if e != nil {
			t.Fatalf("Unexpected error: %s", e)
		}
		if useTLS == "1" {
			c.SetRootCA(tlsRootCA)
			c.EnableTLS()
			c.EnableTLSVerification()
		}
		learn(t, c, request.Spam, th, 2, 0, 0, true)
	} else {
		t.Skip("skipping test; $SPAMD_NETWORK or $SPAMD_ADDRESS not set")
	}
}

func learn(t *testing.T, c *Client, req request.MsgType, th []HeaderCheck, hlen, rawlen, ruleslen int, isspam bool) {
	ir, e := getFile(isspam)
	if e != nil {
		t.Fatalf("Unexpected error: %s", e)
	}
	defer ir.Close()
	r, e := c.Learn(ir, req)
	if e != nil {
		t.Fatalf("Unexpected error: %s", e)
	}
	basicChecks(t, r, request.Tell, th, hlen, false)
	rlen := len(r.Raw)
	if rlen > rawlen {
		t.Errorf("Got %d want %d", rlen, rawlen)
	}
	rlen = len(r.Rules)
	if rlen > ruleslen {
		t.Errorf("Got %d want %d", rlen, ruleslen)
	}
	ir.Seek(0, 0)
	r, e = c.Revoke(ir)
	if e != nil {
		t.Fatalf("Unexpected error: %s", e)
	}
	basicChecks(t, r, request.Tell, th, hlen, false)
	log(t, r)
}

func tell(t *testing.T, c *Client, req request.MsgType, act request.TellAction, th []HeaderCheck, hlen, rawlen, ruleslen int, isspam bool) {
	ir, e := getFile(isspam)
	if e != nil {
		t.Fatalf("Unexpected error: %s", e)
	}
	defer ir.Close()
	r, e := c.Tell(ir, req, act)
	if e != nil {
		t.Fatalf("Unexpected error: %s", e)
	}
	basicChecks(t, r, request.Tell, th, hlen, isspam)
	rlen := len(r.Raw)
	if rlen > rawlen {
		t.Errorf("Got %d want %d", rlen, rawlen)
	}
	rlen = len(r.Rules)
	if rlen > ruleslen {
		t.Errorf("Got %d want %d", rlen, ruleslen)
	}
	log(t, r)
}

func basicChecks(t *testing.T, r *response.Response, req request.Method, th []HeaderCheck, hlen int, isspam bool) {
	if r.RequestMethod != req {
		t.Errorf("Got %q want %q", r.RequestMethod, req)
	}
	if r.StatusCode != response.ExOK {
		t.Errorf("Got %q want %q", r.StatusCode, response.ExOK)
	}
	if r.IsSpam != isspam {
		t.Errorf("Got %t want %t", r.IsSpam, isspam)
	}
	h := len(r.Headers)
	if h > hlen {
		t.Errorf("Got %d want %d", h, hlen)
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
}

func getFn(isspam bool) (p string) {
	if isspam {
		p = "./examples/data/spam.txt"
	} else {
		p = "./examples/data/ham.txt"
	}
	return
}

func getFile(isspam bool) (f *os.File, e error) {
	fn := getFn(isspam)
	f, e = os.Open(fn)
	if e != nil {
		return
	}
	return
}

func getReader(f *os.File, tst int) (ir io.Reader, e error) {
	var msgb []byte
	f.Seek(0, 0)
	switch tst {
	case StringTest:
		msgb, e = ioutil.ReadAll(f)
		if e != nil {
			return
		}
		ir = strings.NewReader(string(msgb))
	case BytesTest:
		msgb, e = ioutil.ReadAll(f)
		if e != nil {
			return
		}
		ir = bytes.NewReader(msgb)
	case BufferTest:
		msgb, e = ioutil.ReadAll(f)
		if e != nil {
			return
		}
		ir = bytes.NewBuffer(msgb)
	case FileTest:
		ir = f
	}

	return
}

func log(t *testing.T, r *response.Response) {
	t.Logf("RequestMethod:\t%s\nStatusCode:\t%s\nStatusMsg:\t%s\nVersion:\t%s\nScore:\t%v\nBaseScore:\t%v\nIsSpam:\t%t\nHeaders:\t%v\nMsg:\t%v\nRules:\t%v",
		r.RequestMethod, r.StatusCode, r.StatusMsg, r.Version, r.Score, r.BaseScore, r.IsSpam, r.Headers, r.Msg, r.Rules)
}
