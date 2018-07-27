// Copyright (C) 2018 Andrew Colin Kissa <andrew@datopdog.io>
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

/*
Package main
Spamc - Golang spamc client
*/
package main

// StatusCode StatusCode
// StatusMsg  string
// Version    string
// Score      float64
// BaseScore  float64
// IsSpam     bool
// Headers    textproto.MIMEHeader
// Msg        *Msg
// Rules      []map[string]string

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"strings"
	"time"

	"github.com/baruwa-enterprise/spamc"
	"github.com/baruwa-enterprise/spamc/request"
	"github.com/baruwa-enterprise/spamc/response"
	flag "github.com/spf13/pflag"
)

var (
	cfg     *Config
	cmdName string
)

// Config holds the configuration
type Config struct {
	Address        string
	Port           int
	UseTLS         bool
	User           string
	UseCompression bool
	RootCA         string
}

func d(r *response.Response) {
	// log.Println("===================================")
	log.Printf("RequestMethod => %v\n", r.RequestMethod)
	log.Printf("StatusCode => %v\n", r.StatusCode)
	log.Printf("StatusMsg => %v\n", r.StatusMsg)
	log.Printf("Version => %v\n", r.Version)
	log.Printf("Score => %v\n", r.Score)
	log.Printf("BaseScore => %v\n", r.BaseScore)
	log.Printf("IsSpam => %v\n", r.IsSpam)
	log.Printf("Headers => %v\n", r.Headers)
	log.Printf("Msg => %v\n", r.Msg)
	log.Printf("Msg.Header => %v\n", r.Msg.Header)
	log.Printf("Msg.Body => %s", r.Msg.Body)
	log.Printf("Msg.Raw => %s", r.Raw)
	log.Printf("Rules => %v\n", r.Rules)
	log.Println("===================================")
}

func init() {
	cfg = &Config{}
	cmdName = path.Base(os.Args[0])
	flag.StringVarP(&cfg.Address, "host", "H", "192.168.1.14",
		`Specify Spamd host to connect to.`)
	flag.IntVarP(&cfg.Port, "port", "p", 783,
		`In TCP/IP mode, connect to spamd server listening on given port`)
	flag.BoolVarP(&cfg.UseTLS, "use-tls", "S", false,
		`Use TLS.`)
	flag.StringVarP(&cfg.User, "user", "u", "exim",
		`User for spamd to process this message under.`)
	flag.BoolVarP(&cfg.UseCompression, "use-compression", "z", false,
		`Compress mail message sent to spamd.`)
	flag.StringVarP(&cfg.RootCA, "root-ca", "r", "/Users/andrew/tmp/frontend-ca.pem",
		`The CA certificate for verifying the TLS connection.`)
}

func parseAddr(a string, p int) (n string, h string) {
	if strings.HasPrefix(a, "/") {
		n = "unix"
		h = a
	} else {
		n = "tcp"
		if strings.Contains(a, ":") {
			h = fmt.Sprintf("[%s]:%d", a, p)
		} else {
			h = fmt.Sprintf("%s:%d", a, p)
		}
	}
	return
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [options]\n", cmdName)
	fmt.Fprint(os.Stderr, "\nOptions:\n")
	flag.PrintDefaults()
}

func main() {
	flag.Usage = usage
	flag.ErrHelp = errors.New("")
	flag.CommandLine.SortFlags = false
	flag.Parse()
	network, address := parseAddr(cfg.Address, cfg.Port)
	ch := make(chan bool)
	m := []byte(`Date: Mon, 23 Jun 2015 11:40:36 -0400
From: Gopher <from@example.com>
To: Another Gopher <to@example.com>
Subject: Gophers at Gophercon
Message-Id: <v0421010eb70653b14e06@[192.168.1.84]>

Message body
James

My Workd

++++++++++++++
`)
	go func(m []byte) {
		defer func() {
			ch <- true
		}()
		c, err := spamc.NewClient(network, address, cfg.User, cfg.UseCompression)
		if err != nil {
			log.Println(err)
			return
		}
		c.SetCmdTimeout(5 * time.Second)
		if cfg.UseTLS {
			err = c.SetRootCA(cfg.RootCA)
			if err != nil {
				log.Println("ERROR:", err)
				return
			}
			c.EnableTLS()
		}
		ir := bytes.NewReader(m)
		r, e := c.Check(ir)
		if e != nil {
			log.Println(e)
			return
		}
		d(r)
	}(m)
	go func(m []byte) {
		c, err := spamc.NewClient(network, address, cfg.User, cfg.UseCompression)
		defer func() {
			ch <- true
		}()
		if err != nil {
			log.Println("ERROR:", err)
			return
		}

		if cfg.UseTLS {
			err = c.SetRootCA(cfg.RootCA)
			if err != nil {
				log.Println("ERROR:", err)
				return
			}
			c.EnableTLS()
		}
		c.EnableRawBody()
		ir := bytes.NewReader(m)
		r, e := c.Headers(ir)
		if e != nil {
			log.Println("ERROR:", e)
			return
		}
		d(r)
	}(m)
	go func(m []byte) {
		c, err := spamc.NewClient(network, address, cfg.User, cfg.UseCompression)
		defer func() {
			ch <- true
		}()
		if err != nil {
			log.Println(err)
			return
		}
		if cfg.UseTLS {
			err = c.SetRootCA(cfg.RootCA)
			if err != nil {
				log.Println("ERROR:", err)
				return
			}
			c.EnableTLS()
		}
		c.EnableRawBody()
		ir := bytes.NewReader(m)
		r, e := c.Process(ir)
		if e != nil {
			log.Println(e)
			return
		}
		d(r)
	}(m)
	go func(m []byte) {
		defer func() {
			ch <- true
		}()
		c, err := spamc.NewClient(network, address, cfg.User, cfg.UseCompression)
		if err != nil {
			log.Println(err)
			return
		}
		if cfg.UseTLS {
			err = c.SetRootCA(cfg.RootCA)
			if err != nil {
				log.Println("ERROR:", err)
				return
			}
			c.EnableTLS()
		}
		c.EnableRawBody()
		ir := bytes.NewReader(m)
		r, e := c.Report(ir)
		if e != nil {
			log.Println(e)
			return
		}
		d(r)
	}(m)
	go func(m []byte) {
		defer func() {
			ch <- true
		}()
		c, err := spamc.NewClient(network, address, cfg.User, cfg.UseCompression)
		if err != nil {
			log.Println(err)
			return
		}
		if cfg.UseTLS {
			err = c.SetRootCA(cfg.RootCA)
			if err != nil {
				log.Println("ERROR:", err)
				return
			}
			c.EnableTLS()
		}
		c.EnableRawBody()
		ir := bytes.NewReader(m)
		r, e := c.ReportIfSpam(ir)
		if e != nil {
			log.Println(e)
			return
		}
		d(r)
	}(m)
	go func(m []byte) {
		defer func() {
			ch <- true
		}()
		c, err := spamc.NewClient(network, address, cfg.User, cfg.UseCompression)
		if err != nil {
			log.Println(err)
			return
		}
		if cfg.UseTLS {
			err = c.SetRootCA(cfg.RootCA)
			if err != nil {
				log.Println("ERROR:", err)
				return
			}
			c.EnableTLS()
		}
		c.EnableRawBody()
		ir := bytes.NewReader(m)
		r, e := c.Symbols(ir)
		if e != nil {
			log.Println(e)
			return
		}
		d(r)
	}(m)
	<-ch
	c, err := spamc.NewClient(network, address, cfg.User, cfg.UseCompression)
	if err != nil {
		log.Println(err)
		return
	}
	if cfg.UseTLS {
		err = c.SetRootCA(cfg.RootCA)
		if err != nil {
			log.Println("ERROR:", err)
			return
		}
		c.EnableTLS()
	}
	// c.SetConnTimeout(2 * time.Second)
	// c.SetCmdTimeout(2 * time.Second)
	// c.SetConnRetries(5)
	ir := bytes.NewReader(m)
	r, e := c.Tell(ir, request.Ham, request.LearnAction)
	if e != nil {
		log.Println(e)
		return
	}
	d(r)
	ir.Reset(m)
	r, e = c.Tell(ir, request.Ham, request.ForgetAction)
	if e != nil {
		log.Println(e)
		return
	}
	d(r)
	ir.Reset(m)
	r, e = c.Tell(ir, request.Spam, request.LearnAction)
	if e != nil {
		log.Println(e)
		return
	}
	d(r)
	ir.Reset(m)
	r, e = c.Tell(ir, request.Spam, request.ForgetAction)
	if e != nil {
		log.Println(e)
		return
	}
	d(r)
}
