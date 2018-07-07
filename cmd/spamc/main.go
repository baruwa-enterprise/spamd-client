// Spamc - Golang spamc client
// Copyright (C) 2018 Andrew Colin Kissa <andrew@datopdog.io>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.
// Package main
package main

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path"
	"time"

	flag "github.com/spf13/pflag"
)

var (
	cfg *Config
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
	fmt.Fprintf(os.Stderr, "Usage: %s [options] [-e command [args]] < message\n", path.Base(os.Args[0]))
	fmt.Fprint(os.Stderr, "\nOptions:\n")
	flag.PrintDefaults()
}

func main() {
	flag.Usage = usage
	flag.ErrHelp = errors.New("")
	flag.CommandLine.SortFlags = false
	flag.Parse()
	// fmt.Printf("%v\n", cfg)
}
