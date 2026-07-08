// Package runespace is a Go client SDK for the RuneSpace encrypted vector index
// service.
//
// RuneSpace is a blind FHE (RNS-CKKS) vector search engine: it holds only the
// PUBLIC evaluation key and never sees plaintext or the secret key. This SDK
// owns the client side of that contract — it generates and manages the evi key
// set, encrypts embeddings and queries locally, drives the RuneSpace gRPC data
// plane, and decrypts search results with the secret key.
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
//	c.RegisterKeys(ctx, keys)            // upload the PUBLIC eval key
//	c.Insert(ctx, "doc-1", embedding)    // encrypts locally, then Insert
//	hits, _ := c.Search(ctx, query, 10)  // encrypts, searches, decrypts, ranks
//	c.Delete(ctx, "doc-1")
//
// # Keys
//
// Keys is the fixed key set for one index dimension. It bundles the
// rmp (IP0) key material; the mm (IP1+/clustered) path is reserved but not yet
// implemented (see ErrUnimplemented). Generate a set once with GenerateKeys,
// then OpenKeys it wherever encrypt/decrypt is needed. There is no load/unload
// lifecycle — register the key set on a client and operate.
//
// # FHE primitives
//
// The FHE primitives come from the bundled libevi (evi-crypto) static archives
// via cgo; see third_party/evi/PROVENANCE for the pinned version and build
// provenance.
package runespace
