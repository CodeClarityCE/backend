package cmd

import (
	"bytes"
	"strings"
	"testing"
)

// result is what a pipeline sees after one CLI run.
type result struct {
	code   int
	stdout string
	stderr string
}

// run runs the CLI with args, as a pipeline step would.
func run(t *testing.T, args ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(args, &stdout, &stderr)
	return result{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

func TestVersionPrintsTheBuildVersion(t *testing.T) {
	isolate(t)
	Version = "1.2.3-test"

	got := run(t, "version")

	if got.code != 0 || strings.TrimSpace(got.stdout) != "codeclarity 1.2.3-test" {
		t.Fatalf("got %+v", got)
	}
}

func TestOnlyThePipelineCommandsRemain(t *testing.T) {
	isolate(t)
	for _, removed := range []string{"project", "analysis", "analyzer", "result", "config", "completion"} {
		got := run(t, removed, "list")
		if got.code == 0 || !strings.Contains(got.stderr, "unknown command") {
			t.Errorf("%s: got %+v", removed, got)
		}
	}
}

// isolate gives the test an empty home and no CodeClarity environment.
func isolate(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	for _, name := range []string{"CODECLARITY_URL", "CODECLARITY_ORG", "CODECLARITY_TOKEN"} {
		t.Setenv(name, "")
	}
}
