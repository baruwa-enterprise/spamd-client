// Copyright (C) 2018-2021 Andrew Colin Kissa <andrew@datopdog.io>
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

/*
Package main
Spamc - Golang Spamc SpamAssassin Client
*/
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/textproto"
	"os"
	"os/user"
	"path"
	"strconv"
	"strings"
	"time"

	spamc "github.com/baruwa-enterprise/spamd-client/pkg"
	"github.com/baruwa-enterprise/spamd-client/pkg/request"
	"github.com/baruwa-enterprise/spamd-client/pkg/response"
	flag "github.com/spf13/pflag"
)

const (
	maxMsgSize      int64 = (256 * 1024 * 1024)
	defaultUnixSock       = "/var/run/spamassassin/spamd.sock"
)

var (
	cfg     *Config
	cmdName string
)

// Config represents the configuration flags
type Config struct {
	Bsmtp               bool
	Check               bool
	Dest                []string
	ExitCode            bool
	Config              string
	Randomize           bool
	LogToStdErr         bool
	LearnType           string
	ReportType          string
	Port                int
	ReportIfSpam        bool
	Report              bool
	MaxSize             int64
	ConnRetry           int
	RetrySleep          int
	FilterRetry         int
	FilterSleep         int
	TLSVersion          string
	TimeOut             int
	ConnTimeOut         int
	User                string
	UnixSocket          string
	Version             bool
	DisableSafeFb       bool
	UnavailableTempfail bool
	Tests               bool
	KeepAliceCheck      bool
	UseCompression      bool
	HeadersOnly         bool
	F                   bool
	UseIPv4             bool
	UseIPv6             bool
	PipeCmd             string
}

func init() {
	rand.Seed(time.Now().UnixNano())
	cmdName = path.Base(os.Args[0])
	cfg = &Config{}
	flag.StringSliceVarP(&cfg.Dest, "dest", "d", []string{"localhost"},
		`Specify one or more hosts to connect to.
`)
	flag.BoolVarP(&cfg.Randomize, "randomize", "H", false,
		`Randomize IP addresses for the looked-up hostname.`)
	flag.IntVarP(&cfg.Port, "port", "p", 783,
		`In TCP/IP mode, connect to spamd server listening on given port
`)
	flag.StringVarP(&cfg.TLSVersion, "ssl", "S", "tlsv1",
		`Use SSL to talk to spamd.`)
	flag.StringVarP(&cfg.UnixSocket, "socket", "U", "",
		`Connect to spamd via UNIX domain sockets.`)
	flag.StringVarP(&cfg.Config, "config", "F", "",
		`Use this configuration file.`)
	flag.IntVarP(&cfg.TimeOut, "timeout", "t", 600,
		`Timeout in seconds for communications to
spamd.`)
	flag.IntVarP(&cfg.ConnTimeOut, "connect-timeout", "n", 600,
		`Timeout in seconds when opening a connection to
spamd.`)
	flag.IntVar(&cfg.FilterRetry, "filter-retries", 1,
		`Retry filtering this many times if the spamd
process fails (usually times out)`)
	flag.IntVar(&cfg.FilterSleep, "filter-retry-sleep", 3,
		`Sleep for this time between failed filter
attempts, in seconds`)
	flag.IntVar(&cfg.ConnRetry, "connect-retries", 3,
		`Try connecting to spamd tcp socket this many times
`)
	flag.IntVar(&cfg.RetrySleep, "retry-sleep", 3,
		`Sleep for this time between attempts to
connect to spamd, in seconds`)
	flag.Int64VarP(&cfg.MaxSize, "max-size", "s", 500000,
		`Specify maximum message size, in bytes.
`)
	flag.StringVarP(&cfg.User, "username", "u", "current user",
		`User for spamd to process this message under.
`)
	flag.StringVarP(&cfg.LearnType, "learntype", "L", "",
		`Learn message as spam, ham or forget to
forget or unlearn the message.`)
	flag.StringVarP(&cfg.ReportType, "reporttype", "C", "",
		`Report message to collaborative filtering
databases.  Report type should be 'report' for
spam or 'revoke' for ham.`)
	flag.BoolVarP(&cfg.Bsmtp, "bsmtp", "B", false,
		`Assume input is a single BSMTP-formatted
message.`)
	flag.BoolVarP(&cfg.Check, "check", "c", false,
		`Just print the summary line and set an exit
code.`)
	flag.BoolVarP(&cfg.Tests, "tests", "y", false,
		`Just print the names of the tests hit.`)
	flag.BoolVarP(&cfg.ReportIfSpam, "full-spam", "r", false,
		`Print full report for messages identified as
spam.`)
	flag.BoolVarP(&cfg.Report, "full", "R", false,
		`Print full report for all messages.`)
	flag.BoolVar(&cfg.HeadersOnly, "headers", false,
		`Rewrite only the message headers.`)
	flag.BoolVarP(&cfg.ExitCode, "exitcode", "E", false,
		`Filter as normal, and set an exit code.`)
	flag.BoolVarP(&cfg.DisableSafeFb, "no-safe-fallback", "x", false,
		`Don't fallback safely.`)
	flag.BoolVarP(&cfg.UnavailableTempfail, "unavailable-tempfail", "X", false,
		`When using -x, turn 'unavailable' error into
'tempfail'. This may be useful for an MTAs
to defer emails with a temporary SMTP error
instead of bouncing with a permanent SMTP
error.`)
	flag.BoolVarP(&cfg.LogToStdErr, "log-to-stderr", "l", false,
		`Log errors and warnings to stderr.`)
	flag.StringVarP(&cfg.PipeCmd, "pipe-to", "e", "",
		`Pipe the output to the given command instead
of stdout. This must be the last option. [Not Supported]`)
	flag.BoolVarP(&cfg.Version, "version", "V", false,
		`Print spamc version and exit.`)
	flag.BoolVarP(&cfg.KeepAliceCheck, "send-ping", "K", false,
		`Keepalive check of spamd.`)
	flag.BoolVarP(&cfg.UseCompression, "use-compression", "z", false,
		`Compress mail message sent to spamd.`)
	flag.BoolVarP(&cfg.F, "compart-f", "f", false,
		`(Now default, ignored.)`)
	flag.BoolVarP(&cfg.UseIPv4, "use-ipv4", "4", false,
		`Use IPv4 only for connecting to server.`)
	flag.BoolVarP(&cfg.UseIPv6, "use-ipv6", "6", false,
		`Use IPv6 only for connecting to server.`)
}

func usage() {
	fmt.Fprintf(os.Stderr, "SpamAssassin Client version %s\n\n", Version)
	fmt.Fprintf(os.Stderr, "Usage: %s [options] [-e command [args]] < message\n", cmdName)
	fmt.Fprint(os.Stderr, "\nOptions:\n")
	flag.PrintDefaults()
}

func main() {
	var err error
	var m *os.File
	var fi os.FileInfo
	var u *user.User
	var c *spamc.Client
	var network, address string

	flag.Usage = usage
	flag.ErrHelp = errors.New("")
	flag.CommandLine.SortFlags = false
	flag.Parse()
	// msg cleared when in ping action

	if cfg.User == "current user" {
		u, err = user.LookupId(strconv.Itoa(os.Geteuid()))
		if err != nil {
			log.Fatal(err)
		}
		cfg.User = u.Username
	}

	if cfg.MaxSize > maxMsgSize {
		usageErr("%s: -s parameter is beyond max of " + strconv.FormatInt(maxMsgSize, 10))
	}

	if cfg.LearnType != "" {
		if cfg.LearnType != "ham" && cfg.LearnType != "spam" && cfg.LearnType != "forget" {
			usageErr("%s: Please specify a legal learn type")
		}
		if cfg.Check {
			usageErr("%s: Learning excludes check only")
		}
		if cfg.KeepAliceCheck {
			usageErr("%s: Learning excludes ping")
		}
		if cfg.ReportIfSpam {
			usageErr("%s: Learning excludes report if spam")
		}
		if cfg.Report {
			usageErr("%s: Learning excludes report")
		}
		if cfg.Tests {
			usageErr("%s: Learning excludes symbols")
		}
		if cfg.ReportType != "" {
			usageErr("%s: Learning excludes reporting to collaborative filtering databases")
		}
	}

	if cfg.ReportType != "" {
		if cfg.ReportType != "report" && cfg.ReportType != "revoke" {
			usageErr("%s: Please specify a legal report type")
		}
	}

	if len(cfg.Dest) == 0 && cfg.UnixSocket == "" {
		//None set, default to using default unix socket
		if _, err = os.Stat(defaultUnixSock); os.IsNotExist(err) {
			usageErr("%s: Please specify -d or -U")
		}
		network = "unix"
		address = defaultUnixSock
	} else if len(cfg.Dest) > 0 {
		network = "tcp"
		if cfg.UseIPv4 {
			network = "tcp4"
		}
		if cfg.UseIPv6 {
			network = "tcp6"
		}
		if network == "tcp" {
			address = parseAddr(cfg.Dest[0], cfg.Port)
		} else {
			for _, addr := range cfg.Dest {
				i := net.ParseIP(addr)
				if i == nil {
					address = parseAddr(addr, cfg.Port)
					break
				}
				if network == "tcp6" && strings.Contains(addr, ":") {
					address = parseAddr(addr, cfg.Port)
					break
				}
				if network == "tcp4" && !strings.Contains(addr, ":") {
					address = parseAddr(addr, cfg.Port)
					break
				}
			}
		}
	}

	m = os.Stdin
	fi, err = m.Stat()
	if err != nil {
		log.Fatal(err)
	}
	if fi.Size() == 0 {
		usage()
		return
	}
	if fi.Size() > cfg.MaxSize {
		log.Fatalf("The file is larger than max allowed")
	}

	ctx := context.Background()
	// Create spamc client instance
	c, err = spamc.NewClient(network, address, cfg.User, cfg.UseCompression)
	if err != nil {
		log.Fatal(err)
	}
	c.SetConnTimeout(time.Duration(cfg.ConnTimeOut) * time.Second)

	// var retcode int
	var success bool
	var code response.StatusCode
	var rs *response.Response
	for i := 0; i < cfg.FilterRetry; i++ {
		success = false
		if cfg.Check {
			rs, err = c.Check(ctx, m)
			if err != nil {
				code = response.ExSoftware
			} else {
				if rs.StatusCode == response.ExOK {
					success = true
					fmt.Printf("%.1f/%.1f\n", rs.Score, rs.BaseScore)
				}
				code = rs.StatusCode
			}
		} else if cfg.Tests {
			c.EnableRawBody()
			rs, err = c.Symbols(ctx, m)
			if err != nil {
				code = response.ExSoftware
			} else {
				if rs.StatusCode == response.ExOK {
					success = true
					fmt.Printf("%s", rs.Raw)
				}
				code = rs.StatusCode
			}
			c.DisableRawBody()
		} else if cfg.ReportIfSpam {
			c.EnableRawBody()
			rs, err = c.ReportIfSpam(ctx, m)
			if err != nil {
				code = response.ExSoftware
			} else {
				if rs.StatusCode == response.ExOK {
					success = true
					fmt.Printf("%.1f/%.1f\n", rs.Score, rs.BaseScore)
					fmt.Printf("%s", rs.Raw)
				}
				code = rs.StatusCode
			}
			c.DisableRawBody()
		} else if cfg.Report {
			c.EnableRawBody()
			rs, err = c.Report(ctx, m)
			if err != nil {
				code = response.ExSoftware
			} else {
				if rs.StatusCode == response.ExOK {
					success = true
					fmt.Printf("%.1f/%.1f\n", rs.Score, rs.BaseScore)
					fmt.Printf("%s", rs.Raw)
				}
				code = rs.StatusCode
			}
			c.DisableRawBody()
		} else if cfg.HeadersOnly {
			c.EnableRawBody()
			rs, err = c.Headers(ctx, m)
			if err != nil {
				code = response.ExSoftware
			} else {
				if rs.StatusCode == response.ExOK {
					success = true
					fmt.Printf("%s", rs.Raw)
					tp := textproto.NewReader(bufio.NewReader(m))
					_, err = tp.ReadMIMEHeader()
					if err == nil {
						for {
							tmp, e := tp.R.ReadBytes('\n')
							if e != nil {
								break
							}
							fmt.Printf("%s", tmp)
						}
					}
				}
				code = rs.StatusCode
			}
			c.DisableRawBody()
		} else if cfg.LearnType != "" || cfg.ReportType != "" {
			success, code = tell(ctx, c, m)
		}
		// retcode = int(code)
		if success && code == response.ExOK || !success && !code.IsTemp() {
			break
		}
		time.Sleep(time.Duration(cfg.RetrySleep) * time.Second)
	}
	// Exit with returned code
	os.Exit(int(code))
}

func usageErr(s string) {
	fmt.Fprintf(os.Stderr, s, cmdName)
	flag.PrintDefaults()
	os.Exit(int(response.ExUsage))
}

func parseAddr(a string, p int) (s string) {
	i := net.ParseIP(a)
	if i == nil {
		s = fmt.Sprintf("%s:%d", a, p)
	} else {
		s = fmt.Sprintf("[%s]:%d", a, p)
	}
	return
}

// func check(c *spamc.Client, m []byte) (succeeded bool, code response.StatusCode) {
// }

func tell(ctx context.Context, c *spamc.Client, m io.Reader) (succeeded bool, code response.StatusCode) {
	var err error
	var h string
	var l request.MsgType
	var a request.TellAction
	var r *response.Response
	if cfg.LearnType != "" || cfg.ReportType != "" {
		if cfg.LearnType == "spam" {
			// learn as spam
			l = request.Spam
			a = request.LearnAction
		} else if cfg.LearnType == "ham" {
			// learn as ham
			l = request.Ham
			a = request.LearnAction
		} else if cfg.LearnType == "forget" {
			//forget
			l = request.Spam
			a = request.ForgetAction
		}
		if cfg.ReportType == "report" {
			//report remote
			l = request.Spam
			a = request.ReportAction
		} else if cfg.ReportType == "revoke" {
			// revoke remote
			l = request.Ham
			a = request.RevokeAction
		}
		r, err = c.Tell(ctx, m, l, a)
		if err != nil {
			code = response.ExSoftware
			return
		}
		code = r.StatusCode
		if r.StatusCode != response.ExOK {
			return
		}
		if cfg.LearnType != "" {
			// learn
			if cfg.LearnType == "forget" {
				h = "Didremove"
			} else {
				h = "Didset"
			}
			if f := r.Headers.Get(h); f != "" {
				fmt.Println("Message successfully un/learned")
			} else {
				fmt.Println("Message was already un/learned")
			}
			return
		}
		if cfg.ReportType != "" {
			// Report
			if cfg.ReportType == "revoke" {
				h = "Didremove"
			} else {
				h = "Didset"
			}
			if f := r.Headers.Get(h); f != "" {
				fmt.Println("Message successfully reported/revoked")
			} else {
				fmt.Println("Unable to report/revoke message")
			}
			return
		}
	}
	return
}
