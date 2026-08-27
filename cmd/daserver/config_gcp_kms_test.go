package main

import (
	"testing"

	"github.com/celestiaorg/op-alt-da/signer"
	"github.com/stretchr/testify/require"
)

func validGCPKMSServerConfig() Config {
	cfg := DefaultConfig()
	cfg.Celestia.Namespace = "00000000000000000000000000000000000000acfe0000000000000000"
	cfg.Celestia.CoreGRPCAddr = "localhost:9090"
	cfg.Celestia.P2PNetwork = "celestia"
	cfg.Celestia.Signer = signer.Config{
		Mode: signer.ModeGCPKMS,
		GCPKMS: signer.GCPKMSConfig{
			Project:    "example-project",
			Location:   "us-east1",
			KeyRing:    "celestia",
			Key:        "op-alt-da",
			KeyVersion: "1",
		},
	}
	return cfg
}

func TestConfigValidateGCPKMS(t *testing.T) {
	cfg := validGCPKMSServerConfig()
	require.NoError(t, cfg.Validate())
	require.True(t, cfg.TxClientEnabled())

	rpcCfg := cfg.ToCelestiaRPCConfig()
	require.NotNil(t, rpcCfg.TxClientConfig)
	require.Equal(t, signer.ModeGCPKMS, rpcCfg.TxClientConfig.Signer.Mode)
	require.Equal(t, "1", rpcCfg.TxClientConfig.Signer.GCPKMS.KeyVersion)
}

func TestConfigValidateGCPKMSRequiresPinnedVersion(t *testing.T) {
	cfg := validGCPKMSServerConfig()
	cfg.Celestia.Signer.GCPKMS.KeyVersion = ""
	require.ErrorContains(t, cfg.Validate(), "key_version is required")
	require.False(t, cfg.TxClientEnabled())
}
