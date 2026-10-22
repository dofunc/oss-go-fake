// Command oss-go-fake serves an Alibaba Cloud OSS compatible API backed by a local directory.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/dofunc/oss-go-fake/internal/config"
	"github.com/dofunc/oss-go-fake/internal/protocol"
	"github.com/dofunc/oss-go-fake/internal/protocol/oss"
	"github.com/dofunc/oss-go-fake/internal/protocol/s3"
	"github.com/dofunc/oss-go-fake/internal/server"
	"github.com/dofunc/oss-go-fake/internal/service"
	"github.com/dofunc/oss-go-fake/internal/storage"
	"github.com/dofunc/oss-go-fake/internal/storage/localfs"
)

// version is set by the release build through -ldflags "-X main.version=...".
var version = "dev"

const shutdownTimeout = 10 * time.Second

// configError marks failures caused by flags or the config file; they exit with code 2.
type configError struct{ err error }

func (e configError) Error() string { return e.err.Error() }
func (e configError) Unwrap() error { return e.err }

func main() {
	root := &cobra.Command{Use: "oss-go-fake", SilenceUsage: true}
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return configError{err} })
	root.AddCommand(serveCommand(), versionCommand())
	if err := root.Execute(); err != nil {
		os.Exit(exitCodeOf(err))
	}
}

// exitCodeOf returns 2 for configuration errors, 1 otherwise.
func exitCodeOf(err error) int {
	var ce configError
	if errors.As(err, &ce) || strings.HasPrefix(err.Error(), "unknown command") {
		return 2
	}
	return 1
}

func versionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), version)
			return err
		},
	}
}

func serveCommand() *cobra.Command {
	flags := config.Config{}
	var configPath string
	var accessKeys, buckets []string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve an OSS-compatible API backed by a local directory",
		RunE: func(cmd *cobra.Command, _ []string) error {
			var file config.Config
			if configPath != "" {
				loaded, err := config.Load(configPath)
				if err != nil {
					return configError{err}
				}
				file = loaded
			}
			var err error
			if flags.AccessKeys, err = parseAccessKeys(accessKeys); err != nil {
				return configError{err}
			}
			if flags.Buckets, err = parseBuckets(buckets); err != nil {
				return configError{err}
			}
			cfg := config.Merge(file, flags, cmd.Flags().Changed)
			if err := cfg.Validate(); err != nil {
				return configError{err}
			}
			return serve(cmd, cfg)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "YAML config file")
	cmd.Flags().StringVar(&flags.Listen, "listen", ":8080", "listen address")
	cmd.Flags().StringVar(&flags.DataDir, "data-dir", "./data", "data root directory")
	cmd.Flags().StringVar(&flags.Domain, "domain", "", "base domain for virtual-hosted requests")
	cmd.Flags().StringVar(&flags.Region, "region", "cn-hangzhou", "region checked in V4 credential scopes")
	cmd.Flags().StringSliceVar(&accessKeys, "access-key", nil, "AK:SK, repeatable")
	cmd.Flags().StringSliceVar(&buckets, "bucket", nil, "name[:private|public-read], repeatable")
	cmd.Flags().StringSliceVar(&flags.Protocols, "protocol", []string{"oss"}, "enabled protocols")
	cmd.Flags().StringVar(&flags.LogLevel, "log-level", "info", "debug|info|warn|error")
	return cmd
}

func parseAccessKeys(values []string) ([]config.AccessKey, error) {
	keys := make([]config.AccessKey, 0, len(values))
	for _, v := range values {
		id, secret, ok := strings.Cut(v, ":")
		if !ok || id == "" || secret == "" {
			return nil, fmt.Errorf("--access-key %q must be AK:SK", v)
		}
		keys = append(keys, config.AccessKey{ID: id, Secret: secret})
	}
	return keys, nil
}

func parseBuckets(values []string) ([]config.Bucket, error) {
	buckets := make([]config.Bucket, 0, len(values))
	for _, v := range values {
		name, acl, _ := strings.Cut(v, ":")
		if acl != "" && acl != string(storage.ACLPrivate) && acl != string(storage.ACLPublicRead) {
			return nil, fmt.Errorf("--bucket %q: acl must be private or public-read", v)
		}
		buckets = append(buckets, config.Bucket{Name: name, ACL: acl})
	}
	return buckets, nil
}

// serve runs until SIGINT or SIGTERM, then lets in-flight requests finish.
func serve(cmd *cobra.Command, cfg config.Config) error {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel(cfg.LogLevel)})))

	store, err := localfs.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	svc := service.New(store)
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	cors := make(map[string][]config.CORSRule)
	for _, b := range cfg.Buckets {
		acl := storage.ACLPrivate
		if b.ACL != "" {
			acl = storage.ACL(b.ACL)
		}
		if err := svc.EnsureBucket(ctx, b.Name, acl); err != nil {
			return fmt.Errorf("prepare bucket %s: %w", b.Name, err)
		}
		cors[b.Name] = b.CORS
	}
	secrets := make(map[string]string, len(cfg.AccessKeys))
	for _, k := range cfg.AccessKeys {
		secrets[k.ID] = k.Secret
	}

	handler := oss.New(svc, oss.Options{Domain: cfg.Domain, Region: cfg.Region, AccessKeys: secrets, CORS: cors})
	srv, err := server.Listen(cfg.Listen, []protocol.Protocol{handler}, []protocol.Protocol{s3.Reserved{}})
	if err != nil {
		return err
	}
	// Launchers wait for this line; without it they would wait out their start timeout.
	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "oss-go-fake ready on %s\n", srv.Addr()); err != nil {
		return fmt.Errorf("report readiness: %w", err)
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	served := make(chan error, 1)
	go func() { served <- srv.Serve() }()
	select {
	case err := <-served:
		return err
	case <-ctx.Done():
	}
	slog.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	return <-served
}

func logLevel(name string) slog.Level {
	var level slog.Level
	if err := level.UnmarshalText([]byte(name)); err != nil {
		return slog.LevelInfo
	}
	return level
}
