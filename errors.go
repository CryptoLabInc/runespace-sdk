package runespace

import (
	"errors"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/status"
)

var (
	// ErrAddressRequired is returned by Dial when given an empty address.
	ErrAddressRequired = errors.New("runespace: server address is required")
	// ErrClientClosed is returned by Client methods after Close.
	ErrClientClosed = errors.New("runespace: client is closed")
	// ErrKeysNotRegistered is returned by data-plane calls made before
	// RegisterKeys has bound a key set to the client.
	ErrKeysNotRegistered = errors.New("runespace: keys not registered on client (call RegisterKeys first)")

	// ErrKeysAlreadyExist / ErrKeysNotFound concern the on-disk key set.
	ErrKeysAlreadyExist = errors.New("runespace: key files already exist at path")
	ErrKeysNotFound     = errors.New("runespace: key files not found at path")

	// Key-part guards: a Keys opened without a given KeyPart cannot
	// perform the corresponding operation.
	ErrKeysNotForEncrypt  = errors.New("runespace: keys opened without KeyPartEnc cannot encrypt")
	ErrKeysNotForDecrypt  = errors.New("runespace: keys opened without KeyPartSec cannot decrypt")
	ErrKeysNotForRegister = errors.New("runespace: keys opened without KeyPartEval have no eval key to register")

	// ErrDimMismatch is returned when an Insert/Search vector length does not
	// match the key set dimension.
	ErrDimMismatch = errors.New("runespace: vector length does not match key set dimension")

	// ErrInvalidMetadata is returned by Insert when the metadata document is
	// non-empty but not valid JSON (the server rejects it too).
	ErrInvalidMetadata = errors.New("runespace: metadata must be valid JSON")

	// ErrClusterRequired is returned by Insert when the server exposes no centroid
	// set. Every insert carries a clustered (MM) representation, so a configured
	// clustered tier is mandatory; a flat-only instance cannot accept inserts.
	ErrClusterRequired = errors.New("runespace: server has no centroid set; inserts require a configured clustered tier")

	// ErrCentroidVersionMismatch is returned by insert paths when the item's
	// centroid_set_version does not match the server's loaded set — the set was
	// replaced while this client (or the routing side) held the old one. The
	// caller should InvalidateCentroidCache, refetch/re-route against the new
	// set, and retry the insert once with the same id.
	ErrCentroidVersionMismatch = errors.New("runespace: centroid set version mismatch (set was replaced)")

	// ErrUnimplemented is retained for source compatibility with pre-MM SDK
	// releases. The current RMP and MM paths are implemented and no current API
	// returns this sentinel.
	//
	// Deprecated: no current operation returns ErrUnimplemented.
	ErrUnimplemented = errors.New("runespace: not implemented")
)

// centroidMismatchReason is the ErrorInfo reason the server attaches when an
// insert's centroid_set_version does not match the loaded set (runespace
// internal/server/grpcerr.go, pb.ErrorReason_ERROR_REASON_CENTROID_VERSION_MISMATCH).
const centroidMismatchReason = "ERROR_REASON_CENTROID_VERSION_MISMATCH"

// isCentroidVersionMismatch reports whether a gRPC error carries the server's
// centroid-version-mismatch reason in its ErrorInfo detail.
func isCentroidVersionMismatch(err error) bool {
	st, ok := status.FromError(err)
	if !ok {
		return false
	}
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok && info.GetReason() == centroidMismatchReason {
			return true
		}
	}
	return false
}
