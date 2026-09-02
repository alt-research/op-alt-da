package s3

import (
	"context"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
)

const (
	BackendAWS         = "aws"
	BackendGCS         = "gcs"
	DefaultGCSEndpoint = "https://storage.googleapis.com"
)

type gcsHTTPSignerV4 struct {
	wrapped awss3.HTTPSignerV4
}

func (s *gcsHTTPSignerV4) SignHTTP(
	ctx context.Context,
	credentials aws.Credentials,
	request *http.Request,
	payloadHash string,
	service string,
	region string,
	signingTime time.Time,
	optFns ...func(*v4.SignerOptions),
) error {
	// GCS may alter Accept-Encoding after receiving the request. Excluding it
	// from SigV4 prevents the resulting signature mismatch.
	request.Header.Del("Accept-Encoding")
	return s.wrapped.SignHTTP(ctx, credentials, request, payloadHash, service, region, signingTime, optFns...)
}

// NewGCSProvider creates a fallback provider for the GCS XML API. It starts
// with the unchanged AWS S3 provider and replaces only the SDK client options
// that are required for GCS interoperability.
func NewGCSProvider(ctx context.Context, cfg Config) (*S3Provider, error) {
	if cfg.Endpoint == "" {
		cfg.Endpoint = DefaultGCSEndpoint
	}

	provider, err := NewS3Provider(ctx, cfg)
	if err != nil {
		return nil, err
	}

	opts := provider.client.Options()
	opts.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
	opts.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	opts.HTTPSignerV4 = &gcsHTTPSignerV4{wrapped: opts.HTTPSignerV4}
	provider.client = awss3.New(opts)

	return provider, nil
}
