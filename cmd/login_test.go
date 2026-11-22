package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoginWithATokenFlagStoresItReadableOnlyByTheUser(t *testing.T) {
	isolate(t)
	api := newFakeAPI(t)

	got := run(t, "login", "--url", api.url(), "--org", fakeOrg, "--token", goodToken)

	if got.code != 0 || !strings.Contains(got.stdout, "Logged in to organization "+fakeOrg) {
		t.Fatalf("got %+v", got)
	}
	if strings.Contains(got.stdout+got.stderr, goodToken) {
		t.Fatalf("the token was printed: %+v", got)
	}
	info, err := os.Stat(credentialsFile(t))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("credentials file: %v, %v", info, err)
	}
}

func TestLoginReadsTheTokenFromTheEnvironment(t *testing.T) {
	isolate(t)
	api := newFakeAPI(t)
	t.Setenv("CODECLARITY_TOKEN", goodToken)

	got := run(t, "login", "--url", api.url(), "--org", fakeOrg)

	if got.code != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestLoginRefusesATokenTheInstanceRejects(t *testing.T) {
	isolate(t)
	api := newFakeAPI(t)

	got := run(t, "login", "--url", api.url(), "--org", fakeOrg, "--token", "ccot_wrong")

	if got.code == 0 || !strings.Contains(got.stderr, "Not authenticated") {
		t.Fatalf("got %+v", got)
	}
	if _, err := os.Stat(credentialsFile(t)); !os.IsNotExist(err) {
		t.Fatalf("credentials were stored: %v", err)
	}
}

func TestLoginNeedsAToken(t *testing.T) {
	isolate(t)
	api := newFakeAPI(t)

	got := run(t, "login", "--url", api.url(), "--org", fakeOrg)

	if got.code == 0 || !strings.Contains(got.stderr, "CODECLARITY_TOKEN") {
		t.Fatalf("got %+v", got)
	}
}

func TestLoginHasNoPasswordOption(t *testing.T) {
	isolate(t)

	got := run(t, "login", "--email", "a@b.c", "--password", "x")

	if got.code == 0 || !strings.Contains(got.stderr, "unknown flag") {
		t.Fatalf("got %+v", got)
	}
}

func TestLogoutForgetsTheToken(t *testing.T) {
	isolate(t)
	api := newFakeAPI(t)
	run(t, "login", "--url", api.url(), "--org", fakeOrg, "--token", goodToken)

	got := run(t, "logout")

	if got.code != 0 {
		t.Fatalf("got %+v", got)
	}
	if after := run(t, "results"); after.code == 0 || !strings.Contains(after.stderr, "codeclarity login") {
		t.Fatalf("still logged in: %+v", after)
	}
}

// credentialsFile is where login stores the token, under the test's home.
func credentialsFile(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(home, ".codeclarity", "credentials.json")
}
