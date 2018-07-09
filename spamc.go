// Package spamc Golang spamc client
// Spamc - Golang spamc client
// Copyright (C) 2018 Andrew Colin Kissa <andrew@datopdog.io>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.
package spamc

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
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
	ClientVersion       = "1.5"
	maxCertSize   int64 = 6000
)

var (
	responseRe   = regexp.MustCompile(`^SPAMD/(?P<version>[0-9\.]+)\s(?P<code>[0-9]+)\s(?P<message>[0-9A-Z_]+)$`)
	spamHeaderRe = regexp.MustCompile(`^(?P<isspam>True|False|Yes|No)\s;\s(?P<score>\-?[0-9\.]+)\s\/\s(?P<basescore>[0-9\.]+)`)
	ruleRe       = regexp.MustCompile(`^\s*(?P<score>-?[0-9]+\.?[0-9]?)\s+(?P<name>[A-Z0-9\_]+)\s+(?P<desc>\w+.*)$`)
)

// A Client represents a Spamc client.
type Client struct {
	network            string
	address            string
	user               string
	rootCA             string
	useTLS             bool
	InsecureSkipVerify bool
	useCompression     bool
	returnRawBody      bool
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

// EnableTLS enables TLS
func (c *Client) EnableTLS() {
	c.useTLS = true
}

// DisableTLS disables TLS
func (c *Client) DisableTLS() {
	c.useTLS = false
}

// EnableRawBody enables returning the raw body
func (c *Client) EnableRawBody() {
	c.returnRawBody = true
}

// DisableRawBody enables returning the raw body
func (c *Client) DisableRawBody() {
	c.returnRawBody = false
}

// SetRootCA sets the path to the RootCA file
func (c *Client) SetRootCA(p string) (err error) {
	var s os.FileInfo
	if s, err = os.Stat(p); os.IsNotExist(err) || s.Size() > maxCertSize {
		if err == nil {
			err = fmt.Errorf("The RootCA file: %s is larger than max allowed: %d", p, maxCertSize)
		}
		return
	}
	c.rootCA = p
	return
}

// EnableTLSVerification enables verification of the server certificate
func (c *Client) EnableTLSVerification() {
	c.InsecureSkipVerify = false
}

// DisableTLSVerification disables verification of the server certificate
func (c *Client) DisableTLSVerification() {
	c.InsecureSkipVerify = true
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

func (c *Client) tlsConfig() (conf *tls.Config) {
	conf = &tls.Config{
		InsecureSkipVerify: c.InsecureSkipVerify,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}
	if c.rootCA != "" {
		ca, err := ioutil.ReadFile(c.rootCA)
		if err != nil {
			return
		}
		p := x509.NewCertPool()
		p.AppendCertsFromPEM(ca)
		conf.RootCAs = p
	}
	return
}

func (c *Client) cmd(rq request.Method, a request.TellAction, l request.MsgType, msg []byte) (rs *response.Response, err error) {
	var s, f bool
	var line string
	var lineb []byte
	var conn net.Conn
	var tc *textproto.Conn

	// Setup the socket connection
	if c.useTLS && strings.HasPrefix(c.network, "tcp") {
		conf := c.tlsConfig()
		conn, err = tls.Dial(c.network, c.address, conf)
	} else {
		conn, err = net.Dial(c.network, c.address)
	}

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
	if m == nil {
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
	// TELL returns headers no body

	if rq == request.Ping {
		return
	}

	// Read the headers
	rs.Headers, err = tc.ReadMIMEHeader()
	if err != nil {
		return
	}

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
		if m == nil {
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
		if rq == request.Headers || rq == request.Process {
			var tp *textproto.Reader
			if c.returnRawBody {
				for {
					lineb, err = tc.R.ReadBytes('\n')
					if err != nil {
						if err == io.EOF {
							err = nil
							rs.Raw = rs.Raw[1:]
							break
						}
						return
					}
					if bytes.Equal(lineb, []byte("\r\n")) {
						continue
					}
					rs.Raw = append(rs.Raw, lineb...)
				}
				tp = textproto.NewReader(bufio.NewReader(bytes.NewReader(rs.Raw)))
				rs.Msg.Header, err = tp.ReadMIMEHeader()
			} else {
				rs.Msg.Header, err = tc.ReadMIMEHeader()
			}

			if err != nil {
				return
			}
			s = false
			f = false
			for {
				if c.returnRawBody {
					lineb, err = tp.R.ReadBytes('\n')
				} else {
					lineb, err = tc.R.ReadBytes('\n')
				}

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
					if mb != nil {
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
				lineb, err = tc.R.ReadBytes('\n')
				if err != nil {
					if err == io.EOF {
						err = nil
						rs.Raw = rs.Raw[1:]
					}
					return
				}

				if c.returnRawBody {
					rs.Raw = append(rs.Raw, lineb...)
				}

				if !s && !bytes.HasPrefix(lineb, []byte("----")) {
					continue
				}

				if !s {
					s = true
					continue
				}

				if bytes.Equal(lineb, []byte("\n")) {
					continue
				}

				mb := ruleRe.FindSubmatch(bytes.TrimRight(lineb, "\n"))
				if mb == nil {
					err = fmt.Errorf("Invalid Server Response: %s", lineb)
					return
				}

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
		// SYMBOLS
		if rq == request.Symbols {
			lineb, err = tc.R.ReadBytes('\n')
			if err != nil {
				if err == io.EOF {
					err = nil
				} else {
					return
				}
			}

			if c.returnRawBody {
				rs.Raw = append(rs.Raw, lineb...)
				rs.Raw = rs.Raw[1:]
			}

			f = false
			for _, rn := range bytes.Split(lineb, []byte(",")) {
				rd := make(map[string]string)
				rd["score"] = ""
				rd["name"] = string(rn)
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
