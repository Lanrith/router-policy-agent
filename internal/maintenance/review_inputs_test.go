package maintenance_test

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// GitHub dispatch number inputs can arrive as strings. A number-typed reusable
// interface needs explicit JSON decoding before GitHub can schedule its jobs.
// https://github.com/actions/runner/issues/2848
func TestManualReviewInputsAreForwardedAsNumbers(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	files, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := files.Close(); err != nil {
			t.Error(err)
		}
	})
	forwarded := regexp.MustCompile(`(?m)^\s+pr:\s*\$\{\{(.*?)\}\}\s*$`)
	numeric := regexp.MustCompile(`(?i)^\s*fromjson\s*\(.*inputs\.pr.*\)\s*$`)
	cases := []struct {
		name string
		path string
	}{
		{name: "security review", path: ".github/workflows/security-review.yml"},
		{name: "human notification", path: ".github/workflows/request-human-review.yml"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			path := testCase.path
			raw, err := files.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			matches := forwarded.FindAllSubmatch(raw, -1)
			if len(matches) != 1 {
				t.Fatalf("%s: got %d PR forwards, want one", path, len(matches))
			}
			if !numeric.Match(matches[0][1]) {
				t.Errorf("%s: decode the dispatched PR input as a JSON number before the reusable call; got %q",
					path, matches[0][1])
			}
		})
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		info, err := os.Stat(filepath.Join(dir, "go.mod"))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if err == nil && !info.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate the repository's workflow interface")
		}
		dir = parent
	}
}
