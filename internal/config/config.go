// Package config loads the YAML configuration and merges command-line flags on top of it.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

type AccessKey struct {
	ID     string `yaml:"id"`
	Secret string `yaml:"secret"`
}

type CORSRule struct {
	AllowedOrigins []string `yaml:"allowed-origins"`
	AllowedMethods []string `yaml:"allowed-methods"`
	AllowedHeaders []string `yaml:"allowed-headers"`
	ExposeHeaders  []string `yaml:"expose-headers"`
	MaxAgeSeconds  int      `yaml:"max-age-seconds"`
}

type Bucket struct {
	Name string     `yaml:"name"`
	ACL  string     `yaml:"acl"` // private or public-read; empty means private
	CORS []CORSRule `yaml:"cors"`
}

type Config struct {
	Listen     string      `yaml:"listen"`
	DataDir    string      `yaml:"data-dir"`
	Domain     string      `yaml:"domain"`
	Region     string      `yaml:"region"`
	Protocols  []string    `yaml:"protocols"`
	LogLevel   string      `yaml:"log-level"`
	AccessKeys []AccessKey `yaml:"access-keys"`
	Buckets    []Bucket    `yaml:"buckets"`
}

// Default is the configuration with nothing given.
func Default() Config {
	return Config{
		Listen:    ":8080",
		DataDir:   "./data",
		Region:    "cn-hangzhou",
		Protocols: []string{"oss"},
		LogLevel:  "info",
	}
}

// Load reads a YAML file. Unknown keys are errors, so a typo does not pass silently.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	return c, nil
}

// Merge overlays flags on top of the file. Only flags the user actually set take part, which
// is why the caller passes cobra's Changed() answers rather than raw values.
func Merge(file Config, flags Config, changed func(name string) bool) Config {
	c := Default()
	overlay(&c.Listen, file.Listen, true)
	overlay(&c.DataDir, file.DataDir, true)
	overlay(&c.Domain, file.Domain, true)
	overlay(&c.Region, file.Region, true)
	overlay(&c.LogLevel, file.LogLevel, true)
	if len(file.Protocols) > 0 {
		c.Protocols = file.Protocols
	}
	overlay(&c.Listen, flags.Listen, changed("listen"))
	overlay(&c.DataDir, flags.DataDir, changed("data-dir"))
	overlay(&c.Domain, flags.Domain, changed("domain"))
	overlay(&c.Region, flags.Region, changed("region"))
	overlay(&c.LogLevel, flags.LogLevel, changed("log-level"))
	if changed("protocol") {
		c.Protocols = flags.Protocols
	}

	c.AccessKeys = append([]AccessKey(nil), file.AccessKeys...)
	for _, k := range flags.AccessKeys {
		if i := indexOf(c.AccessKeys, func(e AccessKey) bool { return e.ID == k.ID }); i >= 0 {
			c.AccessKeys[i] = k
		} else {
			c.AccessKeys = append(c.AccessKeys, k)
		}
	}

	c.Buckets = append([]Bucket(nil), file.Buckets...)
	for _, b := range flags.Buckets {
		i := indexOf(c.Buckets, func(e Bucket) bool { return e.Name == b.Name })
		switch {
		case i < 0:
			c.Buckets = append(c.Buckets, Bucket{Name: b.Name, ACL: b.ACL})
		case b.ACL != "":
			c.Buckets[i].ACL = b.ACL // CORS rules only ever come from the file
		}
	}
	return c
}

func overlay(dst *string, value string, apply bool) {
	if apply && value != "" {
		*dst = value
	}
}

func indexOf[T any](s []T, match func(T) bool) int {
	for i, e := range s {
		if match(e) {
			return i
		}
	}
	return -1
}

var bucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)

var logLevels = map[string]bool{"debug": true, "info": true, "warn": true, "error": true}

func (c Config) Validate() error {
	if len(c.AccessKeys) == 0 {
		return errors.New("at least one --access-key is required")
	}
	for _, k := range c.AccessKeys {
		if k.ID == "" || k.Secret == "" {
			return fmt.Errorf("access key %q needs both an id and a secret", k.ID)
		}
	}
	for _, b := range c.Buckets {
		if !bucketName.MatchString(b.Name) {
			return fmt.Errorf("bucket name %q is invalid: 3-63 lower-case letters, digits or '-', not starting or ending with '-'", b.Name)
		}
		if b.ACL != "" && b.ACL != "private" && b.ACL != "public-read" {
			return fmt.Errorf("bucket %q: acl must be private or public-read, got %q", b.Name, b.ACL)
		}
	}
	if len(c.Protocols) == 0 {
		return errors.New("at least one protocol is required")
	}
	for _, p := range c.Protocols {
		if p != "oss" {
			return fmt.Errorf("protocol %q is not supported in this release, only oss", p)
		}
	}
	if strings.TrimSpace(c.Region) == "" {
		return errors.New("region must not be empty")
	}
	if !logLevels[c.LogLevel] {
		return fmt.Errorf("log level %q is invalid: debug, info, warn or error", c.LogLevel)
	}
	return nil
}
