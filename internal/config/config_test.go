package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func writeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

const sample = `
listen: ":9000"
data-dir: /srv/data
region: cn-shanghai
access-keys:
  - { id: ak1, secret: sk1 }
  - { id: ak2, secret: sk2 }
buckets:
  - name: attachments
    acl: private
    cors:
      - { allowed-origins: ["*"], allowed-methods: [GET], max-age-seconds: 60 }
`

func load(t *testing.T) Config {
	t.Helper()
	c, err := Load(writeFile(t, sample))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func none(string) bool { return false }

func TestFileOnly(t *testing.T) {
	c := Merge(load(t), Config{}, none)
	if c.Listen != ":9000" || c.DataDir != "/srv/data" || c.Region != "cn-shanghai" || c.LogLevel != "info" {
		t.Fatalf("config = %+v", c)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestFlagsOverrideScalars(t *testing.T) {
	flags := Config{Listen: ":7000", Region: "cn-beijing", DataDir: "./ignored"}
	c := Merge(load(t), flags, func(name string) bool { return name == "listen" || name == "region" })
	if c.Listen != ":7000" || c.Region != "cn-beijing" || c.DataDir != "/srv/data" {
		t.Fatalf("config = %+v", c)
	}
}

func TestAccessKeysMergeByID(t *testing.T) {
	flags := Config{AccessKeys: []AccessKey{{ID: "ak2", Secret: "override"}, {ID: "ak3", Secret: "sk3"}}}
	c := Merge(load(t), flags, none)
	want := []AccessKey{{"ak1", "sk1"}, {"ak2", "override"}, {"ak3", "sk3"}}
	if !slices.Equal(c.AccessKeys, want) {
		t.Fatalf("access keys = %v", c.AccessKeys)
	}
}

func TestBucketFlagOverridesACLKeepsCORS(t *testing.T) {
	flags := Config{Buckets: []Bucket{{Name: "attachments", ACL: "public-read"}, {Name: "extra"}}}
	c := Merge(load(t), flags, none)
	if len(c.Buckets) != 2 || c.Buckets[0].ACL != "public-read" || len(c.Buckets[0].CORS) != 1 || c.Buckets[1].Name != "extra" {
		t.Fatalf("buckets = %+v", c.Buckets)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidate(t *testing.T) {
	base := Merge(load(t), Config{}, none)
	cases := map[string]func(c *Config){
		"no access key":   func(c *Config) { c.AccessKeys = nil },
		"bad bucket name": func(c *Config) { c.Buckets = []Bucket{{Name: "Bad_Name"}} },
		"bad acl":         func(c *Config) { c.Buckets = []Bucket{{Name: "fine", ACL: "public-read-write"}} },
		"s3 protocol":     func(c *Config) { c.Protocols = []string{"s3"} },
		"empty region":    func(c *Config) { c.Region = " " },
		"bad log level":   func(c *Config) { c.LogLevel = "verbose" },
	}
	for name, mutate := range cases {
		c := base
		c.Buckets = slices.Clone(base.Buckets)
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: Validate passed", name)
		}
	}
}

func TestLoadErrors(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("missing file loaded")
	}
	if _, err := Load(writeFile(t, "listen: [unclosed")); err == nil {
		t.Error("broken YAML loaded")
	}
	if _, err := Load(writeFile(t, "lisen: \":9000\"")); err == nil {
		t.Error("unknown key accepted")
	}
}
