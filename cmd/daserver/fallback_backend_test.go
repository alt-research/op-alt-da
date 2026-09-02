package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/celestiaorg/op-alt-da/fallback/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFallbackBackendDefaultsToAWS(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, s3.BackendAWS, cfg.Fallback.S3.Backend)
	assert.Equal(t, s3.BackendAWS, FallbackS3BackendFlag.Value)
}

func TestLoadConfigFromFileFallbackBackend(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, os.WriteFile(configPath, []byte(`
[fallback]
enabled = true
provider = "s3"
mode = "both"

[fallback.s3]
backend = "gcs"
`), 0o600))

	cfg, err := LoadConfigFromFile(configPath)
	require.NoError(t, err)
	assert.Equal(t, s3.BackendGCS, cfg.Fallback.S3.Backend)
}

func TestValidateFallbackBackend(t *testing.T) {
	for _, tc := range []struct {
		name    string
		backend string
		wantErr bool
	}{
		{name: "aws", backend: s3.BackendAWS},
		{name: "gcs", backend: s3.BackendGCS},
		{name: "invalid", backend: "auto", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Celestia.Namespace = strings.Repeat("00", 29)
			cfg.Fallback.Enabled = true
			cfg.Fallback.S3.Backend = tc.backend

			err := cfg.Validate()
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "fallback.s3.backend")
				return
			}
			require.NoError(t, err)
		})
	}
}
