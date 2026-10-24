// Command router-policy-profile builds immutable image policy artifacts.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/lanrith/router-policy-agent/internal/cli"
)

func main() { os.Exit(run()) }

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return cli.RunProfile(ctx, os.Args[1:], cli.CheckIO{Out: os.Stdout, Err: os.Stderr})
}
