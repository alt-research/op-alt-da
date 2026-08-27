//go:build integration
// +build integration

package tests

import (
	"os"
	"testing"

	"github.com/celestiaorg/op-alt-da/signer"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	"github.com/stretchr/testify/require"
)

// TestIntegration_GCPKMSSigner exercises a real GCP Cloud KMS key through ADC.
// It is skipped unless all resource identifiers are supplied. The test signs
// fixed, non-sensitive bytes and does not submit a Celestia transaction.
func TestIntegration_GCPKMSSigner(t *testing.T) {
	project := os.Getenv("GCP_KMS_PROJECT")
	location := os.Getenv("GCP_KMS_LOCATION")
	keyRing := os.Getenv("GCP_KMS_KEY_RING")
	key := os.Getenv("GCP_KMS_KEY")
	keyVersion := os.Getenv("GCP_KMS_KEY_VERSION")
	if project == "" || location == "" || keyRing == "" || key == "" || keyVersion == "" {
		t.Skip("GCP_KMS_PROJECT, GCP_KMS_LOCATION, GCP_KMS_KEY_RING, GCP_KMS_KEY, and GCP_KMS_KEY_VERSION are required")
	}

	keyring, keyName, err := signer.NewKeyring(signer.Config{
		Mode: signer.ModeGCPKMS,
		GCPKMS: signer.GCPKMSConfig{
			Project:    project,
			Location:   location,
			KeyRing:    keyRing,
			Key:        key,
			KeyVersion: keyVersion,
		},
	})
	require.NoError(t, err)

	record, err := keyring.Key(keyName)
	require.NoError(t, err)
	address, err := record.GetAddress()
	require.NoError(t, err)
	t.Logf("GCP KMS Celestia signer address: %s", address.String())

	message := []byte("op-alt-da gcp kms integration test")
	signature, publicKey, err := keyring.Sign(keyName, message, signing.SignMode_SIGN_MODE_DIRECT)
	require.NoError(t, err)
	require.Len(t, signature, 64)
	require.True(t, publicKey.VerifySignature(message, signature))
}
