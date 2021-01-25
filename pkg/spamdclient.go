// Copyright (C) 2018-2021 Andrew Colin Kissa <andrew@datopdog.io>
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

/*
Package spamdclient Golang Spamd SpamAssassin Client
spamd-client - Golang Spamd SpamAssassin Client
*/
package spamdclient

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"context"
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
	"time"

	"github.com/baruwa-enterprise/spamd-client/pkg/header"
	"github.com/baruwa-enterprise/spamd-client/pkg/request"
	"github.com/baruwa-enterprise/spamd-client/pkg/response"
)

const (
	// ClientVersion supported protocol version
	ClientVersion             = "1.5"
	maxCertSize         int64 = 6000
	defaultTimeout            = 15 * time.Second
	defaultSleep              = 1 * time.Second
	defaultCmdTimeout         = 1 * time.Minute
	defaultSock               = "/var/run/spamassassin/spamd.sock"
	invalidRespErr            = "Invalid server response: %s"
	unsupportedProtoErr       = "Protocol: %s is not supported"
	unixSockErr               = "The unix socket: %s does not exist"
	noSizeErr                 = "The content length could not be determined"
	responseReadErr           = "Failed to read server response"
	invalidLearnTypeErr       = "Set the correct learn type"
	rootCASizeErr             = "The RootCA file: %s is larger than max allowed: %d"
)

var (
	responseRe   = regexp.MustCompile(`^SPAMD/(?P<version>[0-9\.]+)\s(?P<code>[0-9]+)\s(?P<message>[0-9A-Z_]+)$`)
	spamHeaderRe = regexp.MustCompile(`^(?P<isspam>True|False|Yes|No)\s;\s(?P<score>\-?[0-9\.]+)\s\/\s(?P<basescore>[0-9\.]+)`)
	ruleRe       = regexp.MustCompile(`(?m)^\s*(?P<score>-?[0-9]+\.?[0-9]?)\s+(?P<name>[A-Z0-9\_]+)\s+(?P<desc>[^\s|-|\d]+.*(?:\n\s{2,}\S.*)?)$`)
	noDigitRe    = regexp.MustCompile(`[^\d\-]`)
)

// A Client represents a Spamd-client.
type Client struct {
	network            string
	address            string
	user               string
	rootCA             string
	useTLS             bool
	insecureSkipVerify bool
	useCompression     bool
	returnRawBody      bool
	connTimeout        time.Duration
	connRetries        int
	connSleep          time.Duration
	cmdTimeout         time.Duration
}

// NewClient returns a new Spamd-client.
func NewClient(network, address, user string, useCompression bool) (c *Client, err error) {
	if network == "" && address == "" {
		network = "unix"
		address = defaultSock
	}

	if network == "unix" || network == "unixpacket" {
		if _, err = os.Stat(address); os.IsNotExist(err) {
			err = fmt.Errorf(unixSockErr, address)
			return
		}
	}

	if network != "unix" && network != "unixpacket" && network != "tcp" && network != "tcp4" && network != "tcp6" {
		err = fmt.Errorf(unsupportedProtoErr, network)
		return
	}

	c = &Client{
		network:        network,
		address:        address,
		user:           user,
		useCompression: useCompression,
		connSleep:      defaultSleep,
		connTimeout:    defaultTimeout,
		cmdTimeout:     defaultCmdTimeout,
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
			err = fmt.Errorf(rootCASizeErr, p, maxCertSize)
		}
		return
	}
	c.rootCA = p
	return
}

// EnableTLSVerification enables verification of the server certificate
func (c *Client) EnableTLSVerification() {
	c.insecureSkipVerify = false
}

// DisableTLSVerification disables verification of the server certificate
func (c *Client) DisableTLSVerification() {
	c.insecureSkipVerify = true
}

// SetConnTimeout sets the connection timeout
func (c *Client) SetConnTimeout(t time.Duration) {
	c.connTimeout = t
}

// SetCmdTimeout sets the cmd timeout
func (c *Client) SetCmdTimeout(t time.Duration) {
	c.cmdTimeout = t
}

// SetConnRetries sets the number of times
// connection is retried
func (c *Client) SetConnRetries(s int) {
	if s < 0 {
		s = 0
	}
	c.connRetries = s
}

// SetConnSleep sets the connection retry sleep
// duration in seconds
func (c *Client) SetConnSleep(s time.Duration) {
	c.connSleep = s
}

// Check requests the SPAMD service to check a message with a CHECK request.
func (c *Client) Check(ctx context.Context, r io.Reader) (rs *response.Response, err error) {
	rs, err = c.cmd(ctx, request.Check, request.NoAction, request.NoneType, r)
	return
}

// Headers requests the SPAMD service to check a message with a
// HEADERS request.
func (c *Client) Headers(ctx context.Context, r io.Reader) (rs *response.Response, err error) {
	rs, err = c.cmd(ctx, request.Headers, request.NoAction, request.NoneType, r)
	return
}

// Ping sends a ping request to the SPAMD service and will receive
// a response if the service is alive.
func (c *Client) Ping(ctx context.Context) (s bool, err error) {
	var rs *response.Response
	rs, err = c.cmd(ctx, request.Ping, request.NoAction, request.NoneType, nil)
	if err == nil {
		s = rs.StatusCode == response.ExOK
	}
	return
}

// Process requests the SPAMD service to check a message with a
// PROCESS request.
func (c *Client) Process(ctx context.Context, r io.Reader) (rs *response.Response, err error) {
	rs, err = c.cmd(ctx, request.Process, request.NoAction, request.NoneType, r)
	return
}

// Report requests the SPAMD service to check a message with a
// REPORT request.
func (c *Client) Report(ctx context.Context, r io.Reader) (rs *response.Response, err error) {
	rs, err = c.cmd(ctx, request.Report, request.NoAction, request.NoneType, r)
	return
}

// ReportIfSpam requests the SPAMD service to check a message with a
// REPORT_IFSPAM request.
func (c *Client) ReportIfSpam(ctx context.Context, r io.Reader) (rs *response.Response, err error) {
	rs, err = c.cmd(ctx, request.ReportIfSpam, request.NoAction, request.NoneType, r)
	return
}

// Symbols requests the SPAMD service to check a message with a
// SYMBOLS request.
func (c *Client) Symbols(ctx context.Context, r io.Reader) (rs *response.Response, err error) {
	rs, err = c.cmd(ctx, request.Symbols, request.NoAction, request.NoneType, r)
	return
}

// Tell instructs the SPAMD service to to mark the message
func (c *Client) Tell(ctx context.Context, r io.Reader, l request.MsgType, a request.TellAction) (rs *response.Response, err error) {
	if l < request.Ham || l > request.Spam {
		err = fmt.Errorf(invalidLearnTypeErr)
		return
	}
	rs, err = c.cmd(ctx, request.Tell, a, l, r)
	return
}

// Learn instructs the SPAMD service to learn tokens from a message
func (c *Client) Learn(ctx context.Context, r io.Reader, l request.MsgType) (rs *response.Response, err error) {
	rs, err = c.Tell(ctx, r, l, request.LearnAction)
	return
}

// Revoke instructs the SPAMD service to revoke tokens from a message
func (c *Client) Revoke(ctx context.Context, r io.Reader) (rs *response.Response, err error) {
	rs, err = c.Tell(ctx, r, request.Ham, request.RevokeAction)
	return
}

func (c *Client) tlsConfig() (conf *tls.Config) {
	var ca []byte
	var err error

	conf = &tls.Config{
		InsecureSkipVerify: c.insecureSkipVerify,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}

	if c.rootCA != "" {
		if ca, err = ioutil.ReadFile(c.rootCA); err != nil {
			return
		}
		p := x509.NewCertPool()
		p.AppendCertsFromPEM(ca)
		conf.RootCAs = p
	}

	return
}

func (c *Client) cmd(ctx context.Context, rq request.Method, a request.TellAction, l request.MsgType, r io.Reader) (rs *response.Response, err error) {
	var line string
	var conn net.Conn
	var tc *textproto.Conn

	// Setup the socket connection
	if conn, err = c.dial(ctx); err != nil {
		return
	}

	if c.cmdTimeout > 0 {
		conn.SetDeadline(time.Now().Add(c.cmdTimeout))
	}

	tc = textproto.NewConn(conn)
	defer tc.Close()

	// Send the request
	id := tc.Next()
	tc.StartRequest(id)
	tc.PrintfLine("%s SPAMC/%s", rq, ClientVersion)

	// Send the headers
	// Content-length needs to be send first
	if r != nil {
		var clen int64
		var stat os.FileInfo
		switch v := r.(type) {
		case *bytes.Buffer:
			clen = int64(v.Len())
		case *bytes.Reader:
			clen = int64(v.Len())
		case *strings.Reader:
			clen = int64(v.Len())
		case *os.File:
			if stat, err = v.Stat(); err != nil {
				tc.EndRequest(id)
				return
			}
			clen = stat.Size()
		default:
			err = fmt.Errorf(noSizeErr)
			tc.EndRequest(id)
			return
		}
		clen += 2
		tc.PrintfLine("Content-length: %d", clen)
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
			tc.PrintfLine("%s: %s", header.MessageClass, l)
			tc.PrintfLine("%s: %s", header.Set, "local")
		case request.ForgetAction:
			tc.PrintfLine("%s: %s", header.Remove, "local")
		case request.ReportAction:
			tc.PrintfLine("%s: %s", header.MessageClass, request.Spam)
			tc.PrintfLine("%s: %s", header.Set, "local, remote")
		case request.RevokeAction:
			tc.PrintfLine("%s: %s", header.MessageClass, request.Ham)
			tc.PrintfLine("%s: %s", header.Remove, "remote")
			tc.PrintfLine("%s: %s", header.Set, "local")
		}
	}

	// Send the newline separating headers and body
	tc.PrintfLine("")
	if r != nil {
		// Send the body
		if c.useCompression {
			w := zlib.NewWriter(tc.Writer.W)
			if _, err = io.Copy(w, r); err != nil {
				tc.EndRequest(id)
				return
			}
			w.Close()
		} else {
			if _, err = io.Copy(tc.Writer.W, r); err != nil {
				tc.EndRequest(id)
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
			err = fmt.Errorf(responseReadErr)
		}
		return
	}

	m := responseRe.FindStringSubmatch(line)
	if m == nil {
		err = fmt.Errorf(invalidRespErr, line)
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
	if rs.Headers, err = tc.ReadMIMEHeader(); err != nil {
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
		if err = c.spamHeader(rs); err != nil {
			return
		}
		// HEADERS, PROCESS
		if rq == request.Headers || rq == request.Process {
			err = c.headers(tc, rs)
		}
		// REPORT, REPORT_IFSPAM
		if rq == request.Report || rq == request.ReportIfSpam {
			err = c.report(tc, rs)
		}
		// SYMBOLS
		if rq == request.Symbols {
			err = c.symbols(tc, rs)
		}
	}
	return
}

func (c *Client) dial(ctx context.Context) (conn net.Conn, err error) {
	d := &net.Dialer{}

	if c.connTimeout > 0 {
		d.Timeout = c.connTimeout
	}

	for i := 0; i <= c.connRetries; i++ {
		if c.useTLS && strings.HasPrefix(c.network, "tcp") {
			conf := c.tlsConfig()
			td := tls.Dialer{
				NetDialer: d,
				Config:    conf,
			}
			conn, err = td.DialContext(ctx, c.network, c.address)
		} else {
			conn, err = d.DialContext(ctx, c.network, c.address)
		}
		if e, ok := err.(net.Error); ok && e.Timeout() {
			time.Sleep(c.connSleep)
			continue
		}
		break
	}
	return
}

func (c *Client) spamHeader(rs *response.Response) (err error) {
	line := rs.Headers.Get("Spam")
	m := spamHeaderRe.FindStringSubmatch(line)
	if m == nil {
		err = fmt.Errorf(invalidRespErr, line)
		return
	}
	tv := strings.ToLower(m[1])
	if tv == "true" || tv == "yes" {
		rs.IsSpam = true
	}
	if rs.Score, err = strconv.ParseFloat(m[2], 64); err != nil {
		err = fmt.Errorf(invalidRespErr, err)
		return
	}
	if rs.BaseScore, err = strconv.ParseFloat(m[3], 64); err != nil {
		err = fmt.Errorf(invalidRespErr, err)
		return
	}
	return
}

func (c *Client) headers(tc *textproto.Conn, rs *response.Response) (err error) {
	var s bool
	var lineb []byte
	var tp *textproto.Reader
	if c.returnRawBody {
		for {
			if lineb, err = tc.R.ReadBytes('\n'); err != nil {
				if err == io.EOF {
					err = nil
					break
				}
				return
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

	for {
		if c.returnRawBody {
			lineb, err = tp.R.ReadBytes('\n')
		} else {
			lineb, err = tc.R.ReadBytes('\n')
		}

		if err != nil {
			if err == io.EOF {
				err = nil
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

				rs.Rules = append(rs.Rules, rd)
			}
		}
		if bytes.Equal(lineb, []byte("\r\n")) {
			continue
		}
		rs.Msg.Body = append(rs.Msg.Body, lineb...)
	}
}

func (c *Client) report(tc *textproto.Conn, rs *response.Response) (err error) {
	var s bool
	var lineb []byte
	for {
		if lineb, err = tc.R.ReadBytes('\n'); err != nil {
			if err == io.EOF {
				err = nil
			}
			return
		}

		// Some rules are continued on the next line so
		// for the regex to work further down we need to
		// read the full continued line here
		if !bytes.Equal(lineb, []byte("\n")) {
			if tc.R.Buffered() > 2 {
				peek, e := tc.R.Peek(2)
				if e == nil && isASCIISpace(peek[1]) {
					// read the next line
					var tmpline []byte
					tmpline, err = tc.R.ReadBytes('\n')
					if err == nil {
						lineb = append(lineb, tmpline...)
					}
				}
			}
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
			err = fmt.Errorf(invalidRespErr, lineb)
			return
		}

		rd := make(map[string]string)
		rd["score"] = string(mb[1])
		rd["name"] = string(mb[2])
		rd["description"] = string(mb[3])

		rs.Rules = append(rs.Rules, rd)
	}
}

func (c *Client) symbols(tc *textproto.Conn, rs *response.Response) (err error) {
	var lineb []byte
	if lineb, err = tc.R.ReadBytes('\n'); err != nil {
		if err == io.EOF {
			err = nil
		} else {
			return
		}
	}

	if c.returnRawBody {
		rs.Raw = append(rs.Raw, lineb...)
	}

	for _, rn := range bytes.Split(lineb, []byte(",")) {
		rd := make(map[string]string)
		rd["score"] = ""
		rd["name"] = string(rn)
		rd["description"] = ""

		rs.Rules = append(rs.Rules, rd)
	}
	return
}

func isASCIISpace(b byte) bool {
	return b == ' ' || b == '\t' || noDigitRe.Match([]byte{b})
}
