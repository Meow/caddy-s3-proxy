package s3proxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoEnvironmentAccess fails if a non-test source file of the module
// reads the environment or pulls in the AWS SDK, whose credential chain
// does. Configuration is the only place a variable may be named.
func TestNoEnvironmentAccess(t *testing.T) {
	forbidden := []string{
		"os.Getenv",
		"os.LookupEnv",
		"os.Environ",
		"os.ExpandEnv",
		"ProxyFromEnvironment",
		"aws-sdk-go",
		"aws/aws-sdk",
	}

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var checked int
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		for _, word := range forbidden {
			if strings.Contains(string(src), word) {
				t.Errorf("%s uses %s: the module must not read the environment", name, word)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no source files checked")
	}
}
