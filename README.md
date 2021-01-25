# spamd-client

Golang SpamAssassin Client Library and Commandline tool

[![Ci](https://github.com/baruwa-enterprise/spamd-client/workflows/Ci/badge.svg)](https://github.com/baruwa-enterprise/spamd-client/actions?query=workflow%3ACi)
[![codecov](https://codecov.io/gh/baruwa-enterprise/spamd-client/branch/master/graph/badge.svg)](https://codecov.io/gh/baruwa-enterprise/spamd-client)
[![Go Report Card](https://goreportcard.com/badge/github.com/baruwa-enterprise/spamd-client)](https://goreportcard.com/report/github.com/baruwa-enterprise/spamd-client)
[![Go Reference](https://pkg.go.dev/badge/github.com/baruwa-enterprise/spamd-client.svg)](https://pkg.go.dev/github.com/baruwa-enterprise/spamd-client)
[![MPLv2 License](https://img.shields.io/badge/license-MPLv2-blue.svg?style=flat-square)](https://www.mozilla.org/MPL/2.0/)

## Description

spamd-client is a Golang library and cmdline tool that implements the
SPAMC/SPAMD client protocol used by SpamAssassin.

## Requirements

* Golang 1.15.x or higher
* Pflag - github.com/spf13/pflag

## Getting started

### spamd-client client

The spamd-client client can be installed as follows

```console
$ go get github.com/baruwa-enterprise/spamd-client/cmd/spamd-client
```

Or by cloning the repo and then running

```console
$ make build
$ ./bin/spamd-client
```

### spamd-client library

You can import the library in your code

```golang
import "github.com/baruwa-enterprise/spamd-client/pkg"
```

### Testing

``make test``

## License

MPL-2.0
