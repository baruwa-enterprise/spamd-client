# spamc

Golang Spamc Client

[![Build Status](https://travis-ci.org/baruwa-enterprise/spamc.svg?branch=master)](https://travis-ci.org/baruwa-enterprise/spamc)
[![GoDoc](https://godoc.org/github.com/baruwa-enterprise/spamc?status.svg)](https://godoc.org/github.com/baruwa-enterprise/spamc)
[![MPLv2 License](https://img.shields.io/badge/license-MPLv2-blue.svg?style=flat-square)](https://www.mozilla.org/MPL/2.0/)

## Description

spamc is a Golang library and cmdline tool that implements the
SPAMC/SPAMD client protocol used by SpamAssassin.

## Requirements

* Golang 1.9.x or higher
* Pflag - github.com/spf13/pflag

## Getting started

### Spamc client

The spamc client can be installed as follows

```console
$ go get github.com/baruwa-enterprise/spamc/cmd/spamc
```

Or by cloning the repo and then running

```console
$ make build
$ ./bin/spamc
```

### Spamc library

To install the library

```console
go get get github.com/baruwa-enterprise/spamc
```

You can then import it in your code

```golang
import "github.com/baruwa-enterprise/spamc"
```

### Testing

``make test``

## License

MPL-2.0