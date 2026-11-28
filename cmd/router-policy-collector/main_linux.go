// Command router-policy-collector collects bounded local IPv4 ownership evidence.
package main

import (
	"context"
	"github.com/lanrith/router-policy-agent/internal/radius"
	"os"
	"os/signal"
	"slices"
	"syscall"

	"github.com/lanrith/router-policy-agent/internal/cli"
)

func main() { os.Exit(run()) }

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if slices.Equal(os.Args[1:], []string{"-binding-worker"}) {
		if radius.ServeBindingEvidence(ctx, os.Stdin, os.Stdout) != nil {
			return 1
		}
		return 0
	}
	return cli.RunCollector(ctx, os.Args[1:], cli.CheckIO{Out: os.Stdout, Err: os.Stderr})
}
