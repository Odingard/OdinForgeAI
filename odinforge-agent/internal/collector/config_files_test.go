package collector

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractKeyNames_EnvFile(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")

	content := `# Database config
DATABASE_URL=postgres://localhost/mydb
API_KEY=sk-live-abcdef123456
NORMAL_VAR=hello
export AWS_SECRET_ACCESS_KEY=wJalr...
PASSWORD=supersecret
PORT=3000
`
	if err := os.WriteFile(envPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	keys := extractKeyNames(envPath)

	// Should detect credential-like keys
	keySet := make(map[string]bool)
	for _, k := range keys {
		keySet[k] = true
	}

	expected := []string{"DATABASE_URL", "API_KEY", "AWS_SECRET_ACCESS_KEY", "PASSWORD"}
	for _, e := range expected {
		if !keySet[e] {
			t.Errorf("expected key %q to be detected, got keys: %v", e, keys)
		}
	}

	// Should NOT include non-credential keys
	notExpected := []string{"NORMAL_VAR", "PORT"}
	for _, ne := range notExpected {
		if keySet[ne] {
			t.Errorf("key %q should NOT be detected as credential key", ne)
		}
	}
}

func TestExtractKeyNames_YAMLFile(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "database.yml")

	content := `development:
  adapter: postgresql
  database: myapp_dev
  password: devpass123
  host: localhost
`
	if err := os.WriteFile(yamlPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	keys := extractKeyNames(yamlPath)

	found := false
	for _, k := range keys {
		if k == "password" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'password' key to be detected in YAML, got: %v", keys)
	}
}

func TestExtractKeyNames_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	emptyPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(emptyPath, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}

	keys := extractKeyNames(emptyPath)
	if len(keys) != 0 {
		t.Errorf("expected no keys from empty file, got: %v", keys)
	}
}

func TestExtractKeyNames_NonexistentFile(t *testing.T) {
	keys := extractKeyNames("/nonexistent/path/.env")
	if keys != nil {
		t.Errorf("expected nil for nonexistent file, got: %v", keys)
	}
}

func TestExtractKeyNames_ValuesNotIncluded(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	secret := "super_secret_value_12345"

	content := "API_KEY=" + secret + "\n"
	if err := os.WriteFile(envPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	keys := extractKeyNames(envPath)
	for _, k := range keys {
		if k == secret {
			t.Error("secret VALUE was returned as a key — values must NEVER be extracted")
		}
	}
}
