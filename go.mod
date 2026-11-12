// ASSCOR — Security Acceptability Assessment Runtime
// Licensed under the Apache License, Version 2.0 (see LICENSE).
module github.com/chins-xing/asscor

go 1.26.0

toolchain go1.26.11

require (
	github.com/chins-xing/prism v0.1.0
	github.com/chins-xing/ssam v0.1.0
	golang.org/x/crypto v0.57.0
	golang.org/x/sys v0.48.0
	google.golang.org/grpc v1.83.2
)

require (
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/chins-xing/prism => ./prism-lib

replace github.com/chins-xing/ssam => ./ssam-lib
