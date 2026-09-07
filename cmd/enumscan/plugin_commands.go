package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"enumscan/internal/plugin"
)

func runPluginCommand(command string, args []string) error {
	switch command {
	case "plugin-search":
		flags := flag.NewFlagSet(command, flag.ContinueOnError)
		registryURL := flags.String("registry", "", "explicit HTTPS marketplace registry URL")
		query := flags.String("query", "", "search query")
		if err := flags.Parse(args); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		items, err := plugin.NewMarketplaceManager(*registryURL).SearchPlugins(ctx, *query)
		if err != nil {
			return err
		}
		output, _ := json.MarshalIndent(items, "", "  ")
		fmt.Println(string(output))
		return nil
	case "plugin-install", "plugin-update":
		flags := flag.NewFlagSet(command, flag.ContinueOnError)
		registryURL := flags.String("registry", "", "explicit HTTPS marketplace registry URL")
		id := flags.String("id", "", "plugin id")
		version := flags.String("version", "", "semantic version (latest when omitted)")
		installDir := flags.String("dir", "", "plugin installation directory")
		keyEnv := flags.String("trusted-key-env", "ENUMSCAN_PLUGIN_TRUSTED_PUBLIC_KEY", "environment variable containing trusted Ed25519 public key")
		if err := flags.Parse(args); err != nil {
			return err
		}
		key, err := decodeEd25519PublicKey(os.Getenv(*keyEnv))
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		manager := plugin.NewTrustedMarketplaceManager(*registryURL, key, *installDir)
		var installed string
		if command == "plugin-update" {
			installed, err = manager.Update(ctx, *id)
		} else {
			installed, err = manager.Install(ctx, *id, *version)
		}
		if err != nil {
			return err
		}
		fmt.Println(installed)
		return nil
	case "plugin-rate":
		flags := flag.NewFlagSet(command, flag.ContinueOnError)
		registryURL := flags.String("registry", "", "explicit HTTPS marketplace registry URL")
		id := flags.String("id", "", "plugin id")
		rating := flags.Int("rating", 0, "rating from 1 through 5")
		if err := flags.Parse(args); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return plugin.NewMarketplaceManager(*registryURL).RatePlugin(ctx, *id, *rating)
	case "plugin-registry":
		flags := flag.NewFlagSet(command, flag.ContinueOnError)
		listen := flags.String("listen", "127.0.0.1:9443", "registry listen address")
		baseURL := flags.String("base-url", "", "public HTTPS registry base URL")
		catalog := flags.String("catalog", "", "signed publication catalog JSON")
		keyEnv := flags.String("signing-key-env", "ENUMSCAN_PLUGIN_SIGNING_PRIVATE_KEY", "environment variable containing Ed25519 private key")
		cert := flags.String("tls-cert", "", "TLS certificate")
		keyFile := flags.String("tls-key", "", "TLS private key")
		if err := flags.Parse(args); err != nil {
			return err
		}
		privateKey, err := decodeEd25519PrivateKey(os.Getenv(*keyEnv))
		if err != nil {
			return err
		}
		registry, err := plugin.NewRegistry(*baseURL, privateKey)
		if err != nil {
			return err
		}
		if strings.TrimSpace(*catalog) == "" {
			return fmt.Errorf("plugin registry requires -catalog")
		}
		if err := registry.LoadCatalog(*catalog); err != nil {
			return err
		}
		server := &http.Server{Addr: *listen, Handler: registry, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
		if *cert == "" || *keyFile == "" {
			host, _, _ := net.SplitHostPort(*listen)
			if host != "127.0.0.1" && host != "localhost" && host != "::1" {
				return fmt.Errorf("non-loopback plugin registry requires TLS")
			}
			return server.ListenAndServe()
		}
		return server.ListenAndServeTLS(*cert, *keyFile)
	default:
		return fmt.Errorf("unsupported plugin command %q", command)
	}
}

func decodeEd25519PublicKey(value string) (ed25519.PublicKey, error) {
	data, err := decodePluginKey(value)
	if err != nil || len(data) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("trusted plugin key must be a hex or base64 Ed25519 public key")
	}
	return ed25519.PublicKey(data), nil
}

func decodeEd25519PrivateKey(value string) (ed25519.PrivateKey, error) {
	data, err := decodePluginKey(value)
	if err != nil || len(data) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("plugin signing key must be a hex or base64 Ed25519 private key")
	}
	return ed25519.PrivateKey(data), nil
}

func decodePluginKey(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if data, err := hex.DecodeString(value); err == nil {
		return data, nil
	}
	return base64.StdEncoding.DecodeString(value)
}
