package gosym

import (
	"os/exec"
	"testing"
)

func mustHaveGoBuild(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("skipping; go tool not available in PATH")
	}
}

func goToolPath(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("go")
	if err != nil {
		t.Skip("skipping; go tool not available in PATH")
	}
	return path
}
