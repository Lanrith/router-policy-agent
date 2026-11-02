#!/bin/sh
# Partition the complete tagged suite without changing any test deadline.
# Unit/property tests need their own process: Go otherwise starts their parallel
# work after the serial packet fixtures have consumed most of its global cap.
set -eu

go test -race -shuffle=on -count=1 -tags integration,kernel \
    -skip '^TestKernel' ./internal/firewall
go test -race -shuffle=on -count=1 -tags integration,kernel \
    -run '^TestKernel' -skip '^TestKernelNamedNAT(46|64)' ./internal/firewall
go test -race -shuffle=on -count=1 -tags integration,kernel \
    -run '^TestKernelNamedNAT46' ./internal/firewall
go test -race -shuffle=on -count=1 -tags integration,kernel \
    -run '^TestKernelNamedNAT64' ./internal/firewall
