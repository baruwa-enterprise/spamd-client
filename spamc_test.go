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
	"testing"
)

func TestBasics(t *testing.T) {
	// Test Non existent socket
	_, e := NewClient("unix", "/tmp/.dumx.sock", "exim", true)
	if e == nil {
		t.Errorf("An error should be returned as sock does not exist")
	} else {
		expected := "The unix socket: /tmp/.dumx.sock does not exist"
		if e.Error() != expected {
			t.Errorf("Expected %q want %q", expected, e)
		}
	}
	// Test defaults
	_, e = NewClient("", "", "exim", true)
	if e == nil {
		t.Errorf("An error should be returned as sock does not exist")
	} else {
		expected := "The unix socket: /var/run/spamassassin/spamd.sock does not exist"
		if e.Error() != expected {
			t.Errorf("Got %q want %q", expected, e)
		}
	}
	// Test udp
	_, e = NewClient("udp", "127.1.1.1:4010", "exim", true)
	if e == nil {
		t.Errorf("Expected an error got nil")
	} else {
		expected := "Protocol: udp is not supported"
		if e.Error() != expected {
			t.Errorf("Got %q want %q", expected, e)
		}
	}
	// Test tcp
	network := "tcp"
	address := "127.1.1.1:4010"
	c, e := NewClient(network, address, "exim", true)
	if e != nil {
		t.Errorf("An error should not be returned")
	} else {
		if c.network != network {
			t.Errorf("Got %q want %q", c.network, network)
		}
		if c.address != address {
			t.Errorf("Got %q want %q", c.address, address)
		}
	}
}
