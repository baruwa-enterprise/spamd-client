// Package spamc Golang spamc client
// Spamc - Golang spamc client
// Copyright (C) 2018 Andrew Colin Kissa <andrew@datopdog.io>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.
package spamc

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/baruwa-enterprise/spamc/header"
	"github.com/baruwa-enterprise/spamc/request"
	"github.com/baruwa-enterprise/spamc/response"
)

const (
	ClientVersion = "1.5"
)

var (
	responseRe   = regexp.MustCompile(`^SPAMD/(?P<version>[0-9\.]+)\s(?P<code>[0-9]+)\s(?P<message>[0-9A-Z_]+)$`)
	spamHeaderRe = regexp.MustCompile(`^(?P<isspam>True|False|Yes|No)\s;\s(?P<score>\-?[0-9\.]+)\s\/\s(?P<basescore>[0-9\.]+)`)
	ruleRe       = regexp.MustCompile(`^\s*(?P<score>-?[0-9]+\.?[0-9]?)\s+(?P<name>[A-Z0-9\_]+)\s+(?P<desc>\w+.*)$`)
)

// A Client represents a Spamc client.
type Client struct {
	network        string
	address        string
	user           string
	useCompression bool
}

// NewClient returns a new Spamc client.
func NewClient(network, address, user string, useCompression bool) (c *Client, err error) {
	if network == "" && address == "" {
		network = "unix"
		address = "/var/run/spamassassin/spamd.sock"
	}

	if network == "unix" || network == "unixpacket" {
		if _, err = os.Stat(address); os.IsNotExist(err) {
			err = fmt.Errorf("The unix socket: %s does not exist", address)
			return
		}
	}

	c = &Client{
		network:        network,
		address:        address,
		user:           user,
		useCompression: useCompression,
	}
	return
}

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

// Check requests the SPAMD service to check a message with a CHECK request.
func (c *Client) Check(m []byte) (rs *response.Response, err error) {
	rs, err = c.cmd(request.Check, request.NoAction, request.NoneType, m)
	return
}

// Headers requests the SPAMD service to check a message with a
// HEADERS request.
func (c *Client) Headers(m []byte) (rs *response.Response, err error) {
	rs, err = c.cmd(request.Headers, request.NoAction, request.NoneType, m)
	return
}

// Ping sends a ping request to the SPAMD service and will receive
// a response if the service is alive.
func (c *Client) Ping() (s bool, err error) {
	var rs *response.Response
	rs, err = c.cmd(request.Ping, request.NoAction, request.NoneType, nil)
	s = rs.StatusCode == response.ExOK
	return
}

// Process requests the SPAMD service to check a message with a
// PROCESS request.
func (c *Client) Process(m []byte) (rs *response.Response, err error) {
	rs, err = c.cmd(request.Process, request.NoAction, request.NoneType, m)
	return
}

// Report requests the SPAMD service to check a message with a
// REPORT request.
func (c *Client) Report(m []byte) (rs *response.Response, err error) {
	rs, err = c.cmd(request.Report, request.NoAction, request.NoneType, m)
	return
}

// ReportIfSpam requests the SPAMD service to check a message with a
// REPORT_IFSPAM request.
func (c *Client) ReportIfSpam(m []byte) (rs *response.Response, err error) {
	rs, err = c.cmd(request.ReportIfSpam, request.NoAction, request.NoneType, m)
	return
}

// Symbols requests the SPAMD service to check a message with a
// SYMBOLS request.
func (c *Client) Symbols(m []byte) (rs *response.Response, err error) {
	rs, err = c.cmd(request.Symbols, request.NoAction, request.NoneType, m)
	return
}

// Tell instructs the SPAMD service to to mark the message
func (c *Client) Tell(m []byte, l request.MsgType, a request.TellAction) (rs *response.Response, err error) {
	if l == request.NoneType {
		err = fmt.Errorf("Set the correct learn type")
		return
	}
	rs, err = c.cmd(request.Tell, a, l, m)
	return
}

// Learn instructs the SPAMD service to learn tokens from a message
func (c *Client) Learn(m []byte, l request.MsgType) (rs *response.Response, err error) {
	rs, err = c.Tell(m, l, request.LearnAction)
	return
}

// Revoke instructs the SPAMD service to revoke tokens from a message
func (c *Client) Revoke(m []byte) (rs *response.Response, err error) {
	rs, err = c.Tell(m, request.Ham, request.RevokeAction)
	return
}

func (c *Client) cmd(rq request.Method, a request.TellAction, l request.MsgType, msg []byte) (rs *response.Response, err error) {
	var s, f bool
	var line string
	var lineb []byte
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
	id := tc.Next()
	tc.StartRequest(id)
	tc.PrintfLine("%s SPAMC/%s", rq, ClientVersion)

	// Send the headers
	// Content-length needs to be send first
	if msg != nil {
		tc.PrintfLine("Content-length: %s", strconv.Itoa(len(msg)+2))
	}
	// Compress
	if c.useCompression && rq.UsesHeader(header.Compress) {
		tc.PrintfLine("Compress: %s", "zlib")
	}
	// User
	if c.user != "" && rq.UsesHeader(header.User) {
		tc.PrintfLine("User: %s", c.user)
	}
	// Tell headers
	if rq == request.Tell {
		switch a {
		case request.LearnAction:
			tc.PrintfLine("%: %s", header.MessageClass, l)
			tc.PrintfLine("%: %s", header.Set, "local")
		case request.ForgetAction:
			tc.PrintfLine("%: %s", header.Remove, "local")
		case request.ReportAction:
			tc.PrintfLine("%: %s", header.MessageClass, request.Spam)
			tc.PrintfLine("%: %s", header.Set, "local, remote")
		case request.RevokeAction:
			tc.PrintfLine("%: %s", header.MessageClass, request.Ham)
			tc.PrintfLine("%: %s", header.Remove, "remote")
			tc.PrintfLine("%: %s", header.Set, "local")
		}
	}

	// Send the newline separating headers and body
	tc.PrintfLine("")
	if msg != nil {
		// Send the body
		if c.useCompression {
			var buf bytes.Buffer
			w := zlib.NewWriter(&buf)
			_, err = w.Write(msg)
			if err != nil {
				return
			}
			w.Close()
			_, err = tc.Writer.W.Write(buf.Bytes())
			if err != nil {
				return
			}
		} else {
			_, err = tc.Writer.W.Write(msg)
			if err != nil {
				return
			}
		}
		tc.PrintfLine("")
	}

	// Close the write side of the socket
	if v, ok := conn.(interface{ CloseWrite() error }); ok {
		v.CloseWrite()
	}

	tc.EndRequest(id)
	tc.StartResponse(id)
	defer tc.EndResponse(id)

	// Read the response
	line, err = tc.ReadLine()
	if err != nil {
		if err == io.EOF {
			err = fmt.Errorf("Failed to read server response")
		}
		return
	}

	m := responseRe.FindStringSubmatch(line)
	if len(m) != 4 {
		if rq != request.Skip {
			err = fmt.Errorf("Invalid Server Response: %s", line)
		}
		return
	}

	rs = response.NewResponse(rq)
	rs.StatusCode = response.StatusCodes[m[3]]
	rs.StatusMsg = m[0]
	rs.Version = m[1]

	// CHECK returns only headers no body
	// HEADERS returns headers and body (modified headers)
	// PING returns no headers and no body
	// PROCESS returns headers and body (modified headers, report and body)
	// REPORT returns headers and body (report)
	// REPORT_IFSPAM returns headers and body (report) if spam else headers only
	// SKIP no response connection closed
	// SYMBOLS returns headers and body (rules matched)
	// TELL returns headers

	if rq == request.Ping {
		return
	}

	// Read the headers
	rs.Headers, err = tc.ReadMIMEHeader()
	if err != nil {
		return
	}
	// log.Printf("xxxxxx => Headers => %v\n", rs.Headers)

	if rq == request.Tell {
		return
	}

	switch rq {
	case request.Check,
		request.Headers,
		request.Process,
		request.Report,
		request.ReportIfSpam,
		request.Symbols:
		// Process spam header
		line = rs.Headers.Get("Spam")
		m = spamHeaderRe.FindStringSubmatch(line)
		if len(m) != 4 {
			err = fmt.Errorf("Invalid Server Response: %s", line)
			return
		}
		tv := strings.ToLower(m[1])
		if tv == "true" || tv == "yes" {
			rs.IsSpam = true
		}
		rs.Score, err = strconv.ParseFloat(m[2], 64)
		if err != nil {
			err = fmt.Errorf("Invalid Server Response: %s", err)
			return
		}
		rs.BaseScore, err = strconv.ParseFloat(m[3], 64)
		if err != nil {
			err = fmt.Errorf("Invalid Server Response: %s", err)
			return
		}
		// HEADERS, PROCESS
		if rq == request.Headers || rq == request.Process || rq == request.Tell {
			rs.Msg.Header, err = tc.ReadMIMEHeader()
			if err != nil {
				return
			}
			s = false
			f = false
			for {
				lineb, err = tc.R.ReadBytes('\n')
				if err != nil {
					if err == io.EOF {
						err = nil
						rs.Msg.Body = rs.Msg.Body[1:]
					}
					return
				}

				if !s && bytes.HasPrefix(lineb, []byte("----")) {
					s = true
				}
				if s {
					mb := ruleRe.FindSubmatch(lineb)
					if len(mb) == 4 {
						rd := make(map[string]string)
						rd["score"] = string(mb[1])
						rd["name"] = string(mb[2])
						rd["description"] = string(mb[3])
						if !f {
							rs.Rules[0] = rd
							f = true
						} else {
							rs.Rules = append(rs.Rules, rd)
						}
					}
				}
				if bytes.Equal(lineb, []byte("\r\n")) {
					continue
				}
				rs.Msg.Body = append(rs.Msg.Body, lineb...)
			}
		}
		// REPORT, REPORT_IFSPAM
		if rq == request.Report || rq == request.ReportIfSpam {
			f = false
			s = false
			for {
				line, err = tc.ReadLine()
				if err != nil {
					if err == io.EOF {
						err = nil
					}
					return
				}

				if !s && !strings.HasPrefix(line, "----") {
					continue
				}

				if !s {
					s = true
					continue
				}

				if line == "" {
					continue
				}

				m = ruleRe.FindStringSubmatch(line)
				if len(m) != 4 {
					err = fmt.Errorf("Invalid Server Response: #%s#", line)
					return
				}

				rd := make(map[string]string)
				rd["score"] = m[1]
				rd["name"] = m[2]
				rd["description"] = m[3]
				if !f {
					rs.Rules[0] = rd
					f = true
				} else {
					rs.Rules = append(rs.Rules, rd)
				}
			}
		}
		// SYMBOLS
		if rq == request.Symbols {
			line, err = tc.ReadLine()
			if err != nil {
				return
			}
			f = false
			for _, rn := range strings.Split(line, ",") {
				rd := make(map[string]string)
				rd["score"] = ""
				rd["name"] = rn
				rd["description"] = ""
				if !f {
					rs.Rules[0] = rd
					f = true
				} else {
					rs.Rules = append(rs.Rules, rd)
				}
			}
		}
	}
	return
}
