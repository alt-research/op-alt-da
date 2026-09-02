package s3

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGCSProvider_UsesGCSCompatibilityOptions(t *testing.T) {
	provider, err := NewGCSProvider(context.Background(), Config{
		Bucket:          "test-bucket",
		Endpoint:        DefaultGCSEndpoint,
		Region:          "auto",
		CredentialType:  "static",
		AccessKeyID:     "test-key",
		AccessKeySecret: "test-secret",
	})
	require.NoError(t, err)

	opts := provider.client.Options()
	assert.True(t, opts.UsePathStyle)
	assert.Equal(t, aws.RequestChecksumCalculationWhenRequired, opts.RequestChecksumCalculation)
	assert.Equal(t, aws.ResponseChecksumValidationWhenRequired, opts.ResponseChecksumValidation)
	assert.IsType(t, &gcsHTTPSignerV4{}, opts.HTTPSignerV4)
}

func TestNewGCSProvider_DefaultsEndpoint(t *testing.T) {
	provider, err := NewGCSProvider(context.Background(), Config{
		Bucket:          "test-bucket",
		Region:          "auto",
		CredentialType:  "static",
		AccessKeyID:     "test-key",
		AccessKeySecret: "test-secret",
	})
	require.NoError(t, err)

	opts := provider.client.Options()
	require.NotNil(t, opts.BaseEndpoint)
	assert.Equal(t, DefaultGCSEndpoint, *opts.BaseEndpoint)
}

func TestNewS3Provider_GCSEndpointDoesNotImplicitlyEnableCompatibility(t *testing.T) {
	provider, err := NewS3Provider(context.Background(), Config{
		Bucket:          "test-bucket",
		Endpoint:        DefaultGCSEndpoint,
		Region:          "auto",
		CredentialType:  "static",
		AccessKeyID:     "test-key",
		AccessKeySecret: "test-secret",
	})
	require.NoError(t, err)

	opts := provider.client.Options()
	assert.True(t, opts.UsePathStyle)
	assert.Equal(t, aws.RequestChecksumCalculationUnset, opts.RequestChecksumCalculation)
	assert.Equal(t, aws.ResponseChecksumValidationUnset, opts.ResponseChecksumValidation)
	_, isGCSSigner := opts.HTTPSignerV4.(*gcsHTTPSignerV4)
	assert.False(t, isGCSSigner)
}

type captureHTTPSignerV4 struct {
	acceptEncoding string
}

func (s *captureHTTPSignerV4) SignHTTP(
	_ context.Context,
	_ aws.Credentials,
	request *http.Request,
	_ string,
	_ string,
	_ string,
	_ time.Time,
	_ ...func(*v4.SignerOptions),
) error {
	s.acceptEncoding = request.Header.Get("Accept-Encoding")
	return nil
}

func TestGCSHTTPSignerV4ExcludesAcceptEncoding(t *testing.T) {
	request, err := http.NewRequest(http.MethodPut, DefaultGCSEndpoint+"/bucket/key", nil)
	require.NoError(t, err)
	request.Header.Set("Accept-Encoding", "identity")

	captured := &captureHTTPSignerV4{}
	signer := &gcsHTTPSignerV4{wrapped: captured}
	require.NoError(t, signer.SignHTTP(
		context.Background(),
		aws.Credentials{},
		request,
		"payload-hash",
		"s3",
		"auto",
		time.Now(),
	))
	assert.Empty(t, captured.acceptEncoding)
}
