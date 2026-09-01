package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"

	"github.com/celestiaorg/op-alt-da/signer"
)

func writeSignerAddressTestConfig(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.toml")
	contents := []byte(`[celestia.signer]
mode = "gcp_kms"

[celestia.signer.gcp_kms]
project = "kms-project"
location = "us-east1"
key_ring = "rollup-utils-op-alt-da-signer"
key = "op-alt-da-celestia-test-signer"
key_version = "1"
credentials_file = ""
`)
	require.NoError(t, os.WriteFile(path, contents, 0o600))
	return path
}

func runSignerAddressTestApp(t *testing.T, resolve signerAddressResolver, args ...string) (string, error) {
	t.Helper()

	var output bytes.Buffer
	app := cli.NewApp()
	app.Writer = &output
	app.Commands = []*cli.Command{newSignerAddressCommand(resolve)}
	err := app.Run(append([]string{"da-server", signerAddressCommandName}, args...))
	return output.String(), err
}

func TestSignerAddressCommandText(t *testing.T) {
	configPath := writeSignerAddressTestConfig(t)

	var received signer.Config
	resolve := func(cfg signer.Config) (signerAddressResult, error) {
		received = cfg
		return signerAddressResult{
			Address:    "celestia1testaddress",
			SignerMode: cfg.Mode,
			KeyName:    "projects/kms-project/locations/us-east1/keyRings/rollup-utils-op-alt-da-signer/cryptoKeys/op-alt-da-celestia-test-signer/cryptoKeyVersions/1",
		}, nil
	}

	output, err := runSignerAddressTestApp(t, resolve, "--config", configPath)
	require.NoError(t, err)
	require.Equal(t, "celestia1testaddress\n", output)
	require.Equal(t, signer.ModeGCPKMS, received.Mode)
	require.Equal(t, "kms-project", received.GCPKMS.Project)
	require.Equal(t, "1", received.GCPKMS.KeyVersion)
}

func TestSignerAddressCommandJSON(t *testing.T) {
	configPath := writeSignerAddressTestConfig(t)
	resolve := func(cfg signer.Config) (signerAddressResult, error) {
		return signerAddressResult{
			Address:    "celestia1testaddress",
			SignerMode: cfg.Mode,
			KeyName:    "projects/kms-project/locations/us-east1/keyRings/rollup-utils-op-alt-da-signer/cryptoKeys/op-alt-da-celestia-test-signer/cryptoKeyVersions/1",
		}, nil
	}

	output, err := runSignerAddressTestApp(t, resolve, "--config", configPath, "--output", "json")
	require.NoError(t, err)
	require.JSONEq(t, `{
		"address": "celestia1testaddress",
		"signer_mode": "gcp_kms",
		"key_name": "projects/kms-project/locations/us-east1/keyRings/rollup-utils-op-alt-da-signer/cryptoKeys/op-alt-da-celestia-test-signer/cryptoKeyVersions/1"
	}`, output)
}

func TestSignerAddressCommandRejectsUnknownOutput(t *testing.T) {
	configPath := writeSignerAddressTestConfig(t)
	resolve := func(cfg signer.Config) (signerAddressResult, error) {
		return signerAddressResult{Address: "celestia1testaddress"}, nil
	}

	_, err := runSignerAddressTestApp(t, resolve, "--config", configPath, "--output", "yaml")
	require.ErrorContains(t, err, `unsupported output format "yaml"`)
}

func TestResolveSignerAddressValidatesBeforeAccess(t *testing.T) {
	_, err := resolveSignerAddress(signer.Config{Mode: signer.ModeGCPKMS})
	require.ErrorContains(t, err, "invalid signer config")
	require.ErrorContains(t, err, "project is required")
}
