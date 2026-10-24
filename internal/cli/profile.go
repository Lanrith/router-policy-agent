package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/lanrith/router-policy-agent/internal/firewall"
)

const (
	profileFilename  = "router-profile.json"
	guardsFilename   = "router-guards.nft"
	metadataFilename = "router-profile-metadata.json"
)

// RunProfile builds immutable image policy artifacts from strict JSON inputs.
// It never reads a router YAML file or observes a running firewall itself.
func RunProfile(ctx context.Context, args []string, streams CheckIO) int {
	if ctx == nil || streams.Out == nil || streams.Err == nil {
		return 2
	}
	var baselinePath, rulesetPath, outputDirectory string
	var version bool
	var messages bytes.Buffer
	flags := flag.NewFlagSet("router-policy-profile", flag.ContinueOnError)
	flags.SetOutput(&messages)
	flags.StringVar(&baselinePath, "baseline", "", "strict normalized policy baseline JSON (required)")
	flags.StringVar(&rulesetPath, "ruleset", "", "complete nftables JSON listing before helper guards (required)")
	flags.StringVar(&outputDirectory, "output-directory", "", "existing empty artifact directory (required)")
	flags.BoolVar(&version, "version", false, "print build version")
	flags.Usage = func() {
		fmt.Fprintln(&messages, "Build pinned image policy artifacts; source router YAML is not accepted.")
		fmt.Fprintln(&messages, "Usage: router-policy-profile -baseline FILE -ruleset FILE -output-directory PATH")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			if _, err := io.Copy(streams.Out, &messages); err != nil {
				return 1
			}
			return 0
		}
		return profileDiagnostic(streams.Err, "invalid flags; use -help", 2)
	}
	if flags.NArg() != 0 {
		return profileDiagnostic(streams.Err, "unexpected positional arguments", 2)
	}
	if version {
		if _, err := fmt.Fprintln(streams.Out, Version); err != nil {
			return 1
		}
		return 0
	}
	if baselinePath == "" || rulesetPath == "" || !helperDirectory(outputDirectory) {
		return profileDiagnostic(streams.Err, "-baseline, -ruleset and a valid -output-directory are required", 2)
	}
	baseline, err := readBounded(baselinePath, 2*1024*1024)
	if err != nil {
		return profileDiagnostic(streams.Err, "baseline input unavailable", 1)
	}
	ruleset, err := readBounded(rulesetPath, 16*1024*1024)
	if err != nil {
		return profileDiagnostic(streams.Err, "ruleset input unavailable", 1)
	}
	artifacts, err := firewall.BuildImageProfile(ctx, baseline, ruleset)
	if err != nil {
		return profileDiagnostic(streams.Err, "profile compilation failed", 1)
	}
	if err := writeProfileArtifacts(outputDirectory, artifacts); err != nil {
		return profileDiagnostic(streams.Err, "artifact publication failed", 1)
	}
	return 0
}

func writeProfileArtifacts(directory string, artifacts firewall.ImageProfileArtifacts) (result error) {
	root, err := os.OpenRoot(filepath.Clean(directory))
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, root.Close()) }()
	files := []struct {
		name string
		data []byte
	}{
		{name: profileFilename, data: artifacts.Profile},
		{name: guardsFilename, data: artifacts.Guards},
		{name: metadataFilename, data: artifacts.Metadata},
	}
	written := make([]string, 0, len(files))
	defer func() {
		if result != nil {
			for _, name := range written {
				_ = root.Remove(name)
			}
		}
	}()
	for _, output := range files {
		if len(output.data) == 0 {
			return errors.New("empty profile artifact")
		}
		file, openErr := root.OpenFile(output.name,
			os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
		if openErr != nil {
			return openErr
		}
		count, writeErr := file.Write(output.data)
		if writeErr == nil && count != len(output.data) {
			writeErr = io.ErrShortWrite
		}
		syncErr := file.Sync()
		closeErr := file.Close()
		if joined := errors.Join(writeErr, syncErr, closeErr); joined != nil {
			return joined
		}
		written = append(written, output.name)
	}
	return nil
}

func profileDiagnostic(writer io.Writer, message string, code int) int {
	if _, err := fmt.Fprintf(writer, "router-policy-profile: %s\n", message); err != nil {
		return 1
	}
	return code
}
