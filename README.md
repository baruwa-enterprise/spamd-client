# spamc

Golang Spamc Client

## Getting started

[![Build Status](https://travis-ci.org/baruwa-enterprise/spamc.svg?branch=master)](https://travis-ci.org/baruwa-enterprise/spamc)
[![GoDoc](https://godoc.org/github.com/baruwa-enterprise/spamc?status.svg)](https://godoc.org/github.com/baruwa-enterprise/spamc)
[![MPLv2 License](https://img.shields.io/badge/license-MPLv2-blue.svg?style=flat-square)](https://www.mozilla.org/MPL/2.0/)

This project requires Go to be installed.

### Spamc client

The spamc client can be installed as follows

```console
$ make build
$ ./bin/spamc
```

Or

```console
$ go get github.com/baruwa-enterprise/spamc/cmd/spamc
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