//go:build e2e

// provision_test.go (A1/A5/A6): the provisioning surface via the process harness —
// the data plane is gated until eval keys are registered (A1), RegisterKeysStream
// rejects every malformed/incomplete stream with the right reason and applies
// nothing (A5), and a second registration is refused (rotation unsupported, A6).
// A1/A5 need no keygen (the server stays unregistered); only A6 registers once.
package e2e

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	pb "github.com/CryptoLabInc/runespace-sdk/pkg/runespacepb"
)

// --- RegisterKeysStream frame builders -------------------------------------

func regHeader(kind pb.KeyKind, totalLen uint64) *pb.RegisterKeysStreamRequest {
	return &pb.RegisterKeysStreamRequest{Payload: &pb.RegisterKeysStreamRequest_Header{
		Header: &pb.KeyHeader{Kind: kind, TotalLen: totalLen, Kid: "t", Preset: "IP0", Dim: 1024, EvalMode: "rmp"},
	}}
}
func regData(b []byte) *pb.RegisterKeysStreamRequest {
	return &pb.RegisterKeysStreamRequest{Payload: &pb.RegisterKeysStreamRequest_Data{Data: b}}
}
func regFooter(sum []byte) *pb.RegisterKeysStreamRequest {
	return &pb.RegisterKeysStreamRequest{Payload: &pb.RegisterKeysStreamRequest_Footer{Footer: &pb.KeyFooter{Sha256: sum}}}
}

// sendRegister streams frames and returns the terminal status (CloseAndRecv). A
// mid-stream Send error (server already closed on a bad frame) is ignored; the
// terminal error is what carries the reason.
func sendRegister(cl pb.RuneSpaceServiceClient, frames ...*pb.RegisterKeysStreamRequest) error {
	stream, err := cl.RegisterKeysStream(context.Background())
	if err != nil {
		return err
	}
	for _, f := range frames {
		if err := stream.Send(f); err != nil {
			break
		}
	}
	_, err = stream.CloseAndRecv()
	return err
}

// validKeyFrames returns a structurally valid header+data+footer triple for kind
// (dummy bytes with a matching sha and length) — enough to pass the stream's
// integrity checks (it does not have to be a loadable eval key for the cases here).
func validKeyFrames(kind pb.KeyKind, data []byte) []*pb.RegisterKeysStreamRequest {
	sum := sha256.Sum256(data)
	return []*pb.RegisterKeysStreamRequest{regHeader(kind, uint64(len(data))), regData(data), regFooter(sum[:])}
}

// TestHarness_BootUnregisteredGating (A1): a freshly booted, unregistered instance
// rejects every data-plane RPC with FAILED_PRECONDITION / KEYS_NOT_REGISTERED.
func TestHarness_BootUnregisteredGating(t *testing.T) {
	s := newServer(t, serverOpts{nprobe: 8})
	s.start() // NOT registered
	cl, ctx := s.rawClient(t)

	_, errI := cl.Insert(ctx, &pb.InsertRequest{Id: "00000000-0000-0000-0000-000000000000",
		RmpItem: &pb.RMPItem{Item: dummyItem}, MmItem: &pb.MMItem{Item: dummyItem}})
	wantReason(t, "insert before register", errI, codes.FailedPrecondition, "ERROR_REASON_KEYS_NOT_REGISTERED")

	_, errS := cl.Search(ctx, &pb.SearchRequest{Query: []float32{1, 2, 3}})
	wantReason(t, "search before register", errS, codes.FailedPrecondition, "ERROR_REASON_KEYS_NOT_REGISTERED")

	_, errD := cl.Delete(ctx, &pb.DeleteRequest{Id: "x"})
	wantReason(t, "delete before register", errD, codes.FailedPrecondition, "ERROR_REASON_KEYS_NOT_REGISTERED")
}

// TestHarness_RegisterIntegrityMatrix (A5): every malformed/incomplete register
// stream is rejected with its reason, and nothing is applied (the instance stays
// unregistered, proven by a gated insert at the end).
func TestHarness_RegisterIntegrityMatrix(t *testing.T) {
	s := newServer(t, serverOpts{nprobe: 8})
	s.start() // stays unregistered across all cases
	cl, ctx := s.rawClient(t)

	good := []byte{1, 2, 3, 4}
	goodSum := sha256.Sum256(good)
	rmpOK := validKeyFrames(pb.KeyKind_KEY_KIND_RMP_EVAL, good)

	cases := []struct {
		name   string
		frames []*pb.RegisterKeysStreamRequest
		code   codes.Code
		reason string
	}{
		{"data before header", []*pb.RegisterKeysStreamRequest{regData(good)},
			codes.InvalidArgument, "ERROR_REASON_EVAL_KEY_INTEGRITY"},
		{"footer before header", []*pb.RegisterKeysStreamRequest{regFooter(goodSum[:])},
			codes.InvalidArgument, "ERROR_REASON_EVAL_KEY_INTEGRITY"},
		{"missing footer", []*pb.RegisterKeysStreamRequest{regHeader(pb.KeyKind_KEY_KIND_RMP_EVAL, 4), regData(good)},
			codes.InvalidArgument, "ERROR_REASON_EVAL_KEY_INTEGRITY"},
		{"length mismatch", []*pb.RegisterKeysStreamRequest{regHeader(pb.KeyKind_KEY_KIND_RMP_EVAL, 99), regData(good), regFooter(goodSum[:])},
			codes.InvalidArgument, "ERROR_REASON_EVAL_KEY_INTEGRITY"},
		{"sha256 mismatch", []*pb.RegisterKeysStreamRequest{regHeader(pb.KeyKind_KEY_KIND_RMP_EVAL, 4), regData(good), regFooter([]byte{0xde, 0xad})},
			codes.InvalidArgument, "ERROR_REASON_EVAL_KEY_INTEGRITY"},
		{"duplicate key", append(append([]*pb.RegisterKeysStreamRequest{}, rmpOK...), rmpOK...),
			codes.InvalidArgument, "ERROR_REASON_EVAL_KEY_INTEGRITY"},
		{"oversize", []*pb.RegisterKeysStreamRequest{regHeader(pb.KeyKind_KEY_KIND_RMP_EVAL, 3<<30)},
			codes.InvalidArgument, "ERROR_REASON_EVAL_KEY_INTEGRITY"},
		{"unknown kind", []*pb.RegisterKeysStreamRequest{regHeader(pb.KeyKind_KEY_KIND_UNSPECIFIED, 4)},
			codes.InvalidArgument, "ERROR_REASON_MISSING_EVAL_KEYS"},
		{"only rmp (missing mm)", rmpOK,
			codes.InvalidArgument, "ERROR_REASON_MISSING_EVAL_KEYS"},
	}
	for _, tc := range cases {
		wantReason(t, tc.name, sendRegister(cl, tc.frames...), tc.code, tc.reason)
	}

	// Nothing was applied: the data plane is still gated.
	_, err := cl.Insert(ctx, &pb.InsertRequest{Id: "00000000-0000-0000-0000-000000000000",
		RmpItem: &pb.RMPItem{Item: dummyItem}, MmItem: &pb.MMItem{Item: dummyItem}})
	wantReason(t, "still unregistered after failed registers", err, codes.FailedPrecondition, "ERROR_REASON_KEYS_NOT_REGISTERED")
}

// TestHarness_RegisterRotationUnsupported (A6): after a successful one-shot
// registration, a second register is refused (rotation unsupported). The second
// attempt is a structurally valid dummy stream — it reaches the engine's one-shot
// check, which rejects before loading anything.
func TestHarness_RegisterRotationUnsupported(t *testing.T) {
	s := newServer(t, serverOpts{nprobe: 8})
	s.start()
	s.register() // real one-shot registration
	s.waitReady(10 * time.Minute)

	cl, _ := s.rawClient(t)
	frames := append(validKeyFrames(pb.KeyKind_KEY_KIND_RMP_EVAL, []byte{1, 2, 3, 4}),
		validKeyFrames(pb.KeyKind_KEY_KIND_MM_EVAL, []byte{5, 6, 7, 8})...)
	err := sendRegister(cl, frames...)
	wantReason(t, "second register", err, codes.FailedPrecondition, "ERROR_REASON_KEY_ROTATION_UNSUPPORTED")
}
