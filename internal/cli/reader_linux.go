package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/lanrith/router-policy-agent/internal/reader"
)

// RunReader starts the reader, validates static configuration or checks a synthetic provider stage.
// The polling loop emits bounded outcomes on stderr. The provider check emits its
// one outcome on stdout and exits successfully only on the expected applied receipt.
func RunReader(ctx context.Context, args []string, streams CheckIO) int {
	return runReader(ctx, args, streams, reader.Run)
}

type readerFunc func(context.Context, string, io.Writer) error

func runReader(ctx context.Context, args []string, streams CheckIO, run readerFunc) int {
	if ctx == nil || streams.Out == nil || streams.Err == nil || run == nil {
		return 2
	}
	var directory string
	var check string
	var checkConfig bool
	var bindDN *string
	var version bool
	var messages bytes.Buffer
	flags := flag.NewFlagSet("router-policy-reader", flag.ContinueOnError)
	flags.SetOutput(&messages)
	flags.StringVar(
		&directory,
		"config-directory",
		"",
		"private reader-owned directory with reader.json and runtime credentials.json",
	)
	flags.Func("check-provider", "qualify one synthetic provider stage (single-page, multi-page, withdrawn, unpaged, or unpaged-withdrawn)", func(stage string) error {
		switch stage {
		case "single-page", "multi-page", "withdrawn", "unpaged", "unpaged-withdrawn":
			check = stage
			return nil
		default:
			return errors.New("unknown provider check stage")
		}
	})
	flags.BoolVar(&checkConfig, "check-config", false, "validate reader.json from stdin offline")
	flags.Func("check-bind-dn", "also validate the lookup DN with -check-config", func(value string) error {
		if bindDN != nil || value == "" {
			return errors.New("one nonempty bind DN required")
		}
		bindDN = &value
		return nil
	})
	flags.BoolVar(&version, "version", false, "print build version")
	flags.Usage = func() {
		fmt.Fprintln(&messages, "Collect fresh LDAPS snapshots and submit to the root helper as a non-root reader.")
		fmt.Fprintln(&messages, "Usage: router-policy-reader -config-directory PATH [-check-provider STAGE]")
		fmt.Fprintln(&messages, "       router-policy-reader -check-config [-check-bind-dn DN] < reader.json")
		fmt.Fprintln(&messages, "Polls every 30s; one 10s collection/submission deadline; never replays a failed snapshot.")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			if _, err := io.Copy(streams.Out, &messages); err != nil {
				return 1
			}
			return 0
		}
		return readerDiagnostic(streams.Err, "invalid flags; use -help", 2)
	}
	if flags.NArg() != 0 {
		return readerDiagnostic(streams.Err, "unexpected positional arguments", 2)
	}
	if checkConfig {
		allowed := 1
		if bindDN != nil {
			allowed++
		}
		if flags.NFlag() != allowed {
			return readerDiagnostic(streams.Err, "incompatible flags", 2)
		}
		if err := reader.CheckConfig(streams.In, bindDN); err != nil {
			return readerDiagnostic(streams.Err, "invalid reader configuration", 1)
		}
		if _, err := fmt.Fprintln(streams.Out, `{"result":"pass"}`); err != nil {
			return 1
		}
		return 0
	}
	if bindDN != nil || version && flags.NFlag() != 1 {
		return readerDiagnostic(streams.Err, "incompatible flags", 2)
	}
	if version {
		if _, err := fmt.Fprintln(streams.Out, Version); err != nil {
			return 1
		}
		return 0
	}
	isClean := directory != "/" && filepath.IsAbs(directory) && filepath.Clean(directory) == directory
	isBounded := len(directory) <= 4096 && strings.IndexFunc(directory, unicode.IsControl) < 0
	if !isClean || !isBounded {
		return readerDiagnostic(streams.Err, "valid -config-directory required", 2)
	}
	if check != "" {
		if err := reader.CheckProvider(ctx, directory, streams.Out, check); err != nil {
			return readerDiagnostic(streams.Err, "provider check failed", 1)
		}
		return 0
	}
	err := run(ctx, directory, streams.Err)
	if err == nil || errors.Is(err, context.Canceled) && errors.Is(ctx.Err(), context.Canceled) {
		return 0
	}
	return readerDiagnostic(streams.Err, "runtime unavailable", 1)
}

func readerDiagnostic(writer io.Writer, message string, code int) int {
	if _, err := fmt.Fprintf(writer, "router-policy-reader: %s\n", message); err != nil {
		return 1
	}
	return code
}
