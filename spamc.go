// Package spamc Golang spamc client
// Spamc - Golang spamc client
// Copyright (C) 2018 Andrew Colin Kissa <andrew@datopdog.io>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.
package spamc

import (
	"fmt"
	"net"
	"net/textproto"
	"regexp"

	"github.com/baruwa-enterprise/spamc/request"
	"github.com/baruwa-enterprise/spamc/response"
)

// A Client represents a client connection to a Spamc server.
type Client struct {
	network        string
	address        string
	user           string
	useCompression bool
}

// NewClient returns a new a client connection to a Spamc server.
func NewClient(network, address, user string, useCompression bool) (*Client, error) {
	return &Client{
		network:        network,
		address:        address,
		user:           user,
		useCompression: useCompression,
	}, nil
}

// Dial returns a new Client connected to a Spamc server at addr.
// func Dial(network, addr string) (*Client, error) {
// 	c, err := textproto.Dial(network, addr)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return NewClient(c)
// }

// SetUser sets the user
func (c *Client) SetUser(u string) {
	c.user = u
}

// EnableCompression enables compression
func (c *Client) EnableCompression() {
	c.useCompression = true
}

// DisableCompression disables compression
func (c *Client) DisableCompression() {
	c.useCompression = false
}

// Close closes the connection.
// func (c *Client) Close() error {
// 	return c.conn.Close()
// }

// Check requests the SPAMD service to check a message with a CHECK request.
func (c *Client) Check() {

}

// Headers requests the SPAMD service to check a message with a
// HEADERS request.
func (c *Client) Headers() {

}

// Ping sends a ping request to the SPAMD service and will receive
// a response if the service is alive.
func (c *Client) Ping() (s bool, err error) {
	// err = c.conn.PrintfLine("PING SPAMC/%s", clientversion)
	// if err != nil {
	// 	return
	// }
	// var resp string
	// resp, err = c.conn.ReadLine()
	// if strings.HasPrefix(resp, "SPAMD") && strings.HasSuffix(resp, "PONG") {
	// 	s = true
	// }
	return
}

// Process requests the SPAMD service to check a message with a
// PROCESS request.
func (c *Client) Process(msg []byte) {

}

// Report requests the SPAMD service to check a message with a
// REPORT request.
func (c *Client) Report() {

}

// ReportIfSpam requests the SPAMD service to check a message with a
// REPORT_IFSPAM request.
func (c *Client) ReportIfSpam() {

}

// Symbols requests the SPAMD service to check a message with a
// SYMBOLS request.
func (c *Client) Symbols() {

}

// Tell instructs the SPAMD service to to mark the message
func (c *Client) Tell() {

}

func (c *Client) cmd(rq request.Request) (rs *response.Response, err error) {
	var line string
	var conn net.Conn
	var tc *textproto.Conn

	// Setup the socket connection
	conn, err = net.Dial(c.network, c.address)
	if err != nil {
		return
	}

	tc = textproto.NewConn(conn)
	defer tc.Close()

	// Send the request
	tc.PrintfLine(rq.Request())

	// Send the headers
	// Content-length needs to be send first
	if v := rq.Headers.Get("Content-length"); v != "" {
		tc.PrintfLine("Content-Length: %s", v)
	}
	for h, v := range rq.Headers {
		if h == "Content-Length" {
			continue
		}
		for _, vi := range v {
			tc.PrintfLine("%s: %s", h, vi)
		}
	}

	// Send the newline separating headers and body
	tc.PrintfLine("")
	if rq.Body != nil {
		// Send the body
		_, err = tc.Writer.W.Write(rq.Body)
		if err != nil {
			return
		}
		tc.PrintfLine("")
	}

	// Close the write side of the socket
	if v, ok := conn.(interface{ CloseWrite() error }); ok {
		v.CloseWrite()
	}

	// Read the response
	line, err = tc.ReadLine()
	if err != nil {
		return
	}

	rp := regexp.MustCompile(`^SPAMD/(?P<version>[0-9\.]+)\s(?P<code>[0-9]+)\s(?P<message>[0-9A-Z_]+)$`)
	m := rp.FindStringSubmatch(line)
	if len(m) != 4 {
		err = fmt.Errorf("Invalid Server Response")
		return
	}
	rs = &response.Response{}
	rs.StatusCode = response.StatusCodes[m[3]]
	rs.StatusMsg = m[0]
	rs.Version = m[1]
	rs.Headers, err = tc.ReadMIMEHeader()
	if err != nil {
		return
	}
	return
}
