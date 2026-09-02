//go:build integration

package s3

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/require"
)

func TestIntegration_GCSXMLFallback(t *testing.T) {
	accessKeyID := os.Getenv("GCS_HMAC_ACCESS_ID")
	accessKeySecret := os.Getenv("GCS_HMAC_SECRET")
	bucket := os.Getenv("GCS_BUCKET")
	if accessKeyID == "" || accessKeySecret == "" || bucket == "" {
		t.Skip("GCS_HMAC_ACCESS_ID, GCS_HMAC_SECRET, and GCS_BUCKET are required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	prefix := fmt.Sprintf("op-alt-da-integration/%d", time.Now().UnixNano())
	provider, err := NewGCSProvider(ctx, Config{
		Bucket:          bucket,
		Prefix:          prefix,
		Endpoint:        "https://storage.googleapis.com",
		Region:          "auto",
		CredentialType:  "static",
		AccessKeyID:     accessKeyID,
		AccessKeySecret: accessKeySecret,
		Timeout:         30 * time.Second,
	})
	require.NoError(t, err)

	commitment := []byte("op-alt-da-gcs-integration-commitment")
	payload := []byte("op-alt-da-gcs-integration-payload")
	key := provider.makeKey(commitment)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_, cleanupErr := provider.client.DeleteObject(cleanupCtx, &awss3.DeleteObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		})
		require.NoError(t, cleanupErr)
	})

	require.NoError(t, provider.Put(ctx, commitment, payload))
	retrieved, err := provider.Get(ctx, commitment)
	require.NoError(t, err)
	require.Equal(t, payload, retrieved)
}
