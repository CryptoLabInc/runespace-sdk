package runespace

import (
	"time"

	"google.golang.org/grpc"
)

const (
	defaultKeepaliveTime    = 30 * time.Second
	defaultKeepaliveTimeout = 10 * time.Second
	defaultMaxMsgSize       = 100 * 1024 * 1024 // FHE ciphertexts are large.
)

type clientOptions struct {
	AccessToken       string
	KeepaliveTime     time.Duration
	KeepaliveTimeout  time.Duration
	MaxMsgSize        int
	Insecure          bool
	UnaryInterceptors []grpc.UnaryClientInterceptor
}

func defaultClientOptions() clientOptions {
	return clientOptions{
		KeepaliveTime:    defaultKeepaliveTime,
		KeepaliveTimeout: defaultKeepaliveTimeout,
		MaxMsgSize:       defaultMaxMsgSize,
	}
}

// ClientOption configures Dial. Apply via the With* helpers below.
type ClientOption func(*clientOptions)

// WithAccessToken attaches a bearer token to every RPC via the "authorization"
// metadata header.
func WithAccessToken(token string) ClientOption {
	return func(o *clientOptions) { o.AccessToken = token }
}

// WithKeepaliveTime sets the gRPC client keepalive ping interval.
func WithKeepaliveTime(d time.Duration) ClientOption {
	return func(o *clientOptions) { o.KeepaliveTime = d }
}

// WithKeepaliveTimeout sets how long the client waits for a keepalive ack.
func WithKeepaliveTimeout(d time.Duration) ClientOption {
	return func(o *clientOptions) { o.KeepaliveTimeout = d }
}

// WithMaxMsgSize overrides the max send/recv message size (bytes).
func WithMaxMsgSize(n int) ClientOption {
	return func(o *clientOptions) { o.MaxMsgSize = n }
}

// WithInsecure disables transport security, connecting over a plaintext
// (h2c) gRPC connection instead of TLS.
//
// DEVELOPMENT/TESTING ONLY. This sends FHE ciphertexts, eval keys, and bearer
// tokens in cleartext with no server authentication, so the connection is open
// to eavesdropping and man-in-the-middle attacks. Never enable it against a
// production or remote server — use it solely for a RuneSpace server running on
// localhost during local testing.
func WithInsecure() ClientOption {
	return func(o *clientOptions) { o.Insecure = true }
}

// WithUnaryInterceptor appends a unary client interceptor. Interceptors run in
// the order they were added (after the built-in auth interceptor, if any).
func WithUnaryInterceptor(i grpc.UnaryClientInterceptor) ClientOption {
	return func(o *clientOptions) { o.UnaryInterceptors = append(o.UnaryInterceptors, i) }
}
