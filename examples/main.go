// Spamc - Golang spamc client
// Copyright (C) 2018 Andrew Colin Kissa <andrew@datopdog.io>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.
// Package main
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
	"log"

	"github.com/baruwa-enterprise/spamc"
	"github.com/baruwa-enterprise/spamc/request"
	"github.com/baruwa-enterprise/spamc/response"
)

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
	log.Printf("Rules => %v\n", r.Rules)
	log.Println("===================================")
}

func main() {
	ch := make(chan bool)
	// c, e := spamc.NewClient("unix", "/Users/andrew/tmp/spamd.sock", "", false)
	// c, err := spamc.NewClient("tcp4", "192.168.1.14:783", "exim", true)
	// c, e := spamc.NewClient("tcp4", "192.168.1.12:783", "Debian-exim", true)
	// if err != nil {
	// 	log.Fatal(err)
	// }
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
	// var s bool
	// s, err = c.Ping()
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// log.Println("Pong =>", s)
	// log.Println("===================================")
	go func(m []byte) {
		c, err := spamc.NewClient("tcp4", "192.168.1.14:783", "exim", true)
		if err != nil {
			log.Fatal(err)
		}
		r, e := c.Check(m)
		if e != nil {
			log.Fatal(e)
		}
		d(r)
		ch <- true
	}(m)
	go func(m []byte) {
		c, err := spamc.NewClient("tcp4", "192.168.1.14:783", "exim", true)
		if err != nil {
			log.Fatal(err)
		}
		r, e := c.Headers(m)
		if e != nil {
			log.Fatal(e)
		}
		d(r)
		ch <- true
	}(m)
	go func(m []byte) {
		c, err := spamc.NewClient("tcp4", "192.168.1.14:783", "exim", true)
		if err != nil {
			log.Fatal(err)
		}
		r, e := c.Process(m)
		if e != nil {
			log.Fatal(e)
		}
		d(r)
		ch <- true
	}(m)
	go func(m []byte) {
		c, err := spamc.NewClient("tcp4", "192.168.1.14:783", "exim", true)
		if err != nil {
			log.Fatal(err)
		}
		r, e := c.Report(m)
		if e != nil {
			log.Fatal(e)
		}
		d(r)
		ch <- true
	}(m)
	go func(m []byte) {
		c, err := spamc.NewClient("tcp4", "192.168.1.14:783", "exim", true)
		if err != nil {
			log.Fatal(err)
		}
		r, e := c.ReportIfSpam(m)
		if e != nil {
			log.Fatal(e)
		}
		d(r)
		ch <- true
	}(m)
	go func(m []byte) {
		c, err := spamc.NewClient("tcp4", "192.168.1.14:783", "exim", true)
		if err != nil {
			log.Fatal(err)
		}
		r, e := c.Symbols(m)
		if e != nil {
			log.Fatal(e)
		}
		d(r)
		ch <- true
	}(m)
	<-ch
	c, err := spamc.NewClient("tcp4", "192.168.1.14:783", "exim", true)
	if err != nil {
		log.Fatal(err)
	}
	r, e := c.Tell(m, request.Ham, request.LearnAction)
	if e != nil {
		log.Fatal(e)
	}
	d(r)
	r, e = c.Tell(m, request.Ham, request.ForgetAction)
	if e != nil {
		log.Fatal(e)
	}
	d(r)
	//
	r, e = c.Tell(m, request.Spam, request.LearnAction)
	if e != nil {
		log.Fatal(e)
	}
	d(r)
	r, e = c.Tell(m, request.Spam, request.ForgetAction)
	if e != nil {
		log.Fatal(e)
	}
	d(r)
}
