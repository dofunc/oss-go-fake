package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

const childEnv = "OSS_GO_FAKE_RUN_MAIN"

// TestMain lets the test binary act as the command: a child started with childEnv set runs
// main() with the arguments after "--".
func TestMain(m *testing.M) {
	if os.Getenv(childEnv) == "1" {
		for i, arg := range os.Args {
			if arg == "--" {
				os.Args = append([]string{"oss-go-fake"}, os.Args[i+1:]...)
				break
			}
		}
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func command(t *testing.T, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], append([]string{"-test.run=^$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), childEnv+"=1")
	return cmd
}

func exitCode(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var stderr bytes.Buffer
	cmd := command(t, args...)
	cmd.Stderr = &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), stderr.String()
	}
	if err != nil {
		t.Fatal(err)
	}
	return 0, stderr.String()
}

func TestConfigurationErrorsExitWith2(t *testing.T) {
	dir := t.TempDir()
	broken := filepath.Join(dir, "broken.yaml")
	if err := os.WriteFile(broken, []byte("listen: [unclosed"), 0o644); err != nil {
		t.Fatal(err)
	}
	data := "--data-dir=" + filepath.Join(dir, "data")
	cases := []struct {
		name    string
		args    []string
		message string
	}{
		{"no access key", []string{"serve", data}, "at least one --access-key is required"},
		{"access key without colon", []string{"serve", data, "--access-key", "nocolon"}, "must be AK:SK"},
		{"bad bucket acl", []string{"serve", data, "--access-key", "ak:sk", "--bucket", "b1x:public"}, "acl must be"},
		{"s3 protocol", []string{"serve", data, "--access-key", "ak:sk", "--protocol", "s3"}, "not supported"},
		{"missing config", []string{"serve", "--config", filepath.Join(dir, "none.yaml")}, "read config"},
		{"broken config", []string{"serve", "--config", broken}, "parse config"},
		{"unknown flag", []string{"serve", "--nope"}, "unknown flag"},
	}
	for _, c := range cases {
		code, stderr := exitCode(t, c.args...)
		if code != 2 || !strings.Contains(stderr, c.message) {
			t.Errorf("%s: exit %d, stderr %q", c.name, code, stderr)
		}
	}
}

func TestVersion(t *testing.T) {
	out, err := command(t, "version").Output()
	if err != nil || strings.TrimSpace(string(out)) != "dev" {
		t.Fatalf("version = %q, %v", out, err)
	}
}

// TestGracefulShutdown starts the server, holds a request open, sends SIGTERM and expects the
// request to finish before the process exits with 0.
func TestGracefulShutdown(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no SIGTERM on Windows")
	}
	cmd := command(t, "serve", "--listen", "127.0.0.1:0", "--data-dir", filepath.Join(t.TempDir(), "data"),
		"--access-key", "ak:sk", "--bucket", "pub:public-read")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	addr, ok := strings.CutPrefix(strings.TrimSpace(line), "oss-go-fake ready on ")
	if !ok {
		t.Fatalf("ready line = %q", line)
	}

	// A signed PUT only succeeds once its whole body has arrived, so the server must keep serving
	// it while the shutdown waits.
	body, feed := io.Pipe()
	req, _ := http.NewRequest("PUT", "http://"+addr+"/pub/k", body)
	req.ContentLength = 6
	date := time.Now().UTC().Format(http.TimeFormat)
	mac := hmac.New(sha1.New, []byte("sk"))
	mac.Write([]byte("PUT\n\n\n" + date + "\n/pub/k"))
	req.Header.Set("Date", date)
	req.Header.Set("Authorization", "OSS ak:"+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	answered := make(chan int, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			answered <- -1
			return
		}
		if err := resp.Body.Close(); err != nil {
			t.Errorf("close response: %v", err)
		}
		answered <- resp.StatusCode
	}()
	if _, err := feed.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if _, err := feed.Write([]byte("def")); err != nil {
		t.Fatal(err)
	}
	if err := feed.Close(); err != nil {
		t.Fatal(err)
	}

	if status := <-answered; status != http.StatusOK {
		t.Fatalf("in-flight request got %d", status)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("exit: %v", err)
	}
}
