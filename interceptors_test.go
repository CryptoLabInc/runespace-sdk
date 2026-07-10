package runespace

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// outgoingAuth returns the single "authorization" value on ctx's outgoing
// metadata, failing the test if it is missing or duplicated.
func outgoingAuth(t *testing.T, ctx context.Context) string {
	t.Helper()
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		t.Fatal("no outgoing metadata on context")
	}
	vals := md.Get("authorization")
	if len(vals) != 1 {
		t.Fatalf("authorization header count = %d, want 1 (%v)", len(vals), vals)
	}
	return vals[0]
}

func TestBearerTokenInterceptorUnary(t *testing.T) {
	var got string
	invoker := func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		got = outgoingAuth(t, ctx)
		return nil
	}
	if err := bearerTokenInterceptor("tok123")(context.Background(), "/svc/Unary", nil, nil, nil, invoker); err != nil {
		t.Fatalf("interceptor returned err: %v", err)
	}
	if want := "Bearer tok123"; got != want {
		t.Errorf("authorization = %q, want %q", got, want)
	}
}

func TestBearerTokenInterceptorStream(t *testing.T) {
	var got string
	streamer := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		got = outgoingAuth(t, ctx)
		return nil, nil
	}
	if _, err := bearerTokenStreamInterceptor("tok123")(context.Background(), &grpc.StreamDesc{}, nil, "/svc/Stream", streamer); err != nil {
		t.Fatalf("interceptor returned err: %v", err)
	}
	if want := "Bearer tok123"; got != want {
		t.Errorf("authorization = %q, want %q", got, want)
	}
}
