// Package runespace is a Go client SDK for the RuneSpace encrypted vector index
// service.
//
// RuneSpace is an FHE (RNS-CKKS) vector index. It holds the public evaluation
// keys but never the secret keys. This SDK owns the client side of that
// contract: it generates and manages the evi key set, encrypts stored item
// vectors locally, drives the RuneSpace gRPC data plane, and decrypts search
// results with the secret keys.
//
// Under the current PCMM search contract, query vectors are sent plaintext to
// RuneSpace and encoded server-side. The metadata argument to Insert is also
// stored as plaintext JSON. Applications that need metadata confidentiality
// must seal it before calling the SDK.
//
// Typical use:
//
//	keys, _ := runespace.OpenKeys(
//		runespace.WithKeyPath("/keys"),
//		runespace.WithKeyID("team-a"),
//		runespace.WithKeyDim(128),
//	)
//	defer keys.Close()
//
//	c, _ := runespace.Dial("runespace.example:51024")
//	defer c.Close()
//
//	c.RegisterKeys(ctx, keys) // upload the PUBLIC RMP + MM eval keys
//	embedding := make([]float32, 128)
//	embedding[0] = 1
//	id, _ := c.Insert(ctx, embedding, `{"title":"example"}`)
//	hits, _ := c.Search(ctx, embedding, 10)
//	_ = hits
//	c.Delete(ctx, id)
//
// # Keys
//
// Keys is the fixed key set for one index dimension. It bundles the RMP (IP0)
// and MM (IP1/clustered) material required by the current dual-tier insert and
// search paths. Generate a set once with GenerateKeys, then OpenKeys it wherever
// encryption or decryption is needed. There is no load/unload lifecycle:
// register the key set on a client, operate, and Close it.
//
// # Key durability
//
// The SecKey files are the only way to decrypt existing search results. Losing
// them makes the corresponding encrypted data permanently unreadable; generating
// replacement keys does not recover it. Back up the complete WithKeyPath root
// (both rmp/ and mm/) to encrypted, access-controlled storage and regularly test
// restoration with OpenKeys and Client.VerifyKeys.
//
// # FHE primitives
//
// The FHE primitives come from the bundled libevi (evi-crypto) static archives
// via cgo; see third_party/evi/PROVENANCE for the pinned version and build
// provenance.
package runespace
