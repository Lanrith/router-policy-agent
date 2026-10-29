package maintenance_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"
)

type maintenanceSource struct {
	Schema                   int    `json:"schema"`
	Repository               string `json:"repository"`
	Commit                   string `json:"source_commit"`
	Version                  string `json:"version"`
	PublicationAudit         string `json:"publication_audit"`
	RetainedAssessment       string `json:"retained_assessment"`
	VerificationRecordSHA256 string `json:"verification_record_sha256"`
	HumanReview              int64  `json:"actual_human_review_id"`
}

type maintenanceWorkflow struct {
	path      string
	callee    string
	collector bool
}

var maintenanceWorkflows = []maintenanceWorkflow{
	{path: ".github/workflows/build-release.yml", callee: "publish-release.yml", collector: true},
	{path: ".github/workflows/update-inputs.yml", callee: "security-proposal.yml"},
	{path: ".github/workflows/security-review.yml", callee: "security-review.yml"},
	{path: ".github/workflows/cleanup-artifacts.yml", callee: "cleanup-artifacts.yml"},
	{path: ".github/workflows/request-human-review.yml", callee: "request-human-review.yml"},
}

// This contract catches partial deployments. Release signatures and source
// approval are verified before the reviewed manifest and pins are proposed.
func TestMaintenanceReferencesMatchReviewedSource(t *testing.T) {
	t.Parallel()
	files, source := reviewedMaintenanceSource(t)
	for _, workflow := range maintenanceWorkflows {
		t.Run(workflow.callee, func(t *testing.T) {
			t.Parallel()
			raw, err := files.ReadFile(workflow.path)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateMaintenanceReferences(raw, workflow, source.Commit); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPartialMaintenanceDeploymentsFailTheContract(t *testing.T) {
	t.Parallel()
	files, source := reviewedMaintenanceSource(t)
	for _, workflow := range maintenanceWorkflows {
		t.Run(workflow.callee, func(t *testing.T) {
			t.Parallel()
			raw, err := files.ReadFile(workflow.path)
			if err != nil {
				t.Fatal(err)
			}
			current := "Lanrith/lanrith/.github/workflows/" + workflow.callee + "@" + source.Commit
			changed := bytes.Replace(raw, []byte(current), []byte(strings.Replace(current, source.Commit, strings.Repeat("0", 40), 1)), 1)
			if bytes.Equal(raw, changed) {
				t.Fatal("fixture did not change the actual reusable workflow reference")
			}
			if err := validateMaintenanceReferences(changed, workflow, source.Commit); err == nil {
				t.Fatal("a partially updated reusable workflow passed the source contract")
			}
			if workflow.collector {
				changed = bytes.Replace(raw, []byte("ref: "+source.Commit), []byte("ref: "+strings.Repeat("0", 40)), 1)
				if bytes.Equal(raw, changed) {
					t.Fatal("fixture did not change the actual release collector reference")
				}
				if err := validateMaintenanceReferences(changed, workflow, source.Commit); err == nil {
					t.Fatal("an obsolete release collector passed the source contract")
				}
			}
		})
	}
}

func reviewedMaintenanceSource(t *testing.T) (*os.Root, maintenanceSource) {
	t.Helper()
	files, err := os.OpenRoot(repositoryRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := files.Close(); err != nil {
			t.Error(err)
		}
	})
	raw, err := files.ReadFile("security/maintenance-source.json")
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var source maintenanceSource
	if err := decoder.Decode(&source); err != nil {
		t.Fatal(err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatal("maintenance source must contain one JSON document")
	}
	if source.Schema != 1 || source.Repository != "Lanrith/lanrith" ||
		!regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(source.Commit) ||
		!regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(source.Version) ||
		!regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(source.VerificationRecordSHA256) || source.HumanReview <= 0 ||
		!strings.HasPrefix(source.PublicationAudit, "https://github.com/Lanrith/lanrith/releases/tag/audit-publication-") ||
		!strings.HasPrefix(source.RetainedAssessment, "https://github.com/Lanrith/lanrith/releases/tag/assessment-") {
		t.Fatal("maintenance source lacks its reviewed release and verification identities")
	}
	return files, source
}

func validateMaintenanceReferences(raw []byte, workflow maintenanceWorkflow, commit string) error {
	uses := regexp.MustCompile(`(?m)^[ \t]+uses:[ \t]+(Lanrith/lanrith/[^ \t\r\n]+)[ \t]*$`)
	refs := uses.FindAllSubmatch(raw, -1)
	want := "Lanrith/lanrith/.github/workflows/" + workflow.callee + "@" + commit
	if len(refs) != 1 || bytes.Count(raw, []byte("Lanrith/lanrith/")) != 1 || string(refs[0][1]) != want {
		return fmt.Errorf("%s: pin the reusable workflow to reviewed source %s", workflow.path, commit)
	}
	repositories := regexp.MustCompile(`(?m)^[ \t]+repository:[ \t]+Lanrith/lanrith[ \t]*$`)
	collectors := regexp.MustCompile(`(?m)^[ \t]+repository:[ \t]+Lanrith/lanrith[ \t]*\r?\n[ \t]+ref:[ \t]+([^ \t\r\n]+)[ \t]*$`)
	wantCollectors := 0
	if workflow.collector {
		wantCollectors = 1
	}
	matches := collectors.FindAllSubmatch(raw, -1)
	if len(repositories.FindAll(raw, -1)) != wantCollectors || len(matches) != wantCollectors ||
		(workflow.collector && string(matches[0][1]) != commit) {
		return fmt.Errorf("%s: pin the release collector to reviewed source %s", workflow.path, commit)
	}
	return nil
}
