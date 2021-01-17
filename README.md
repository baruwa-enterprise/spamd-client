# spamc

Golang Spamc Client

[![Ci](https://github.com/baruwa-enterprise/spamc/workflows/Ci/badge.svg)](https://github.com/baruwa-enterprise/spamc/actions?query=workflow%3ACi)
[![codecov](https://codecov.io/gh/baruwa-enterprise/spamc/branch/master/graph/badge.svg)](https://codecov.io/gh/baruwa-enterprise/spamc)
[![Go Report Card](https://goreportcard.com/badge/github.com/baruwa-enterprise/spamc)](https://goreportcard.com/report/github.com/baruwa-enterprise/spamc)
[![GoDoc](https://godoc.org/github.com/baruwa-enterprise/spamc?status.svg)](https://godoc.org/github.com/baruwa-enterprise/spamc)
[![MPLv2 License](https://img.shields.io/badge/license-MPLv2-blue.svg?style=flat-square)](https://www.mozilla.org/MPL/2.0/)

## Description

spamc is a Golang library and cmdline tool that implements the
SPAMC/SPAMD client protocol used by SpamAssassin.

## Requirements

* Golang 1.10.x or higher
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
go get github.com/baruwa-enterprise/spamc
```

You can then import it in your code

```golang
import "github.com/baruwa-enterprise/spamc"
```

### Testing

``make test``

## License

MPL-2.0
