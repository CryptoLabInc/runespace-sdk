# runespace-sdk

Go client SDK for **RuneSpace** — blind vector search over FHE-encrypted
embeddings (RNS-CKKS). The engine holds only the PUBLIC evaluation key and
never sees plaintext or the secret key; this SDK owns the client side of that
contract: it generates and manages the evi key set, encrypts embeddings and
queries locally, drives the RuneSpace gRPC data plane, and decrypts search
results.

The high-level API is flat — vectors in, scores out:

```go
c, _ := runespace.Dial(addr)
c.RegisterKeys(ctx, keys)              // upload the PUBLIC eval key
c.Insert(ctx, "doc-1", embedding)      // encrypts locally, then Insert
hits, _ := c.Search(ctx, query, 10)    // encrypts, searches, decrypts, ranks
c.Delete(ctx, "doc-1")
```

> The MM (clustered, IP1+) key path is reserved but **not yet implemented**;
> `Keys.MMEvalKey` returns `ErrUnimplemented` and `RegisterKeys`
> sends an empty `mm_eval_key`. Only the RMP (IP0) path is wired today.

## Requirements

This SDK binds the libevi FHE primitives via cgo. Every machine that compiles a
binary depending on `runespace-sdk` needs:

- Go 1.26.4 or newer (pinned in `go.mod`)
- C toolchain (clang or gcc)
- OpenSSL 3 — `libssl` + `libcrypto`, dev headers included
- C++ standard library (`libc++` on macOS, `libstdc++` on Linux/Windows)
- A host platform with a bundled libevi slice in `third_party/evi/`:
  - `darwin/arm64`
  - `linux/amd64`, `linux/arm64`
  - `windows/amd64`

The libevi static archives (`libevi_c_api.a`, `libevi_crypto.a`, `libdeb.a`,
`libalea.a`) are vendored in-tree, so no external libevi download is required.
See `third_party/evi/PROVENANCE` for the pinned evi-crypto revision.

### Per-platform install

| Platform | One-shot install |
| -------- | ---------------- |
| macOS (Apple Silicon) | `xcode-select --install && brew install openssl@3` |
| Debian / Ubuntu | `apt install build-essential libssl-dev` |
| RHEL / Fedora | `dnf install gcc-c++ make openssl-devel` |
| Alpine | `apk add build-base openssl-dev` |
| Windows | MSYS2 mingw64 shell: `pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl` |

```sh
go version                          # >= 1.26.4
cc --version                        # clang or gcc
pkg-config --modversion openssl     # >= 3.0
```

cgo requires the **target** platform's C toolchain and sysroot — setting
`GOOS`/`GOARCH` alone is not sufficient. Build on a native host (or container)
per target. Platforms with no libevi slice in `third_party/evi/` will not link.

## Install

```sh
go get github.com/CryptoLabInc/runespace-sdk
```

## Quick start

```go
package main

import (
	"context"
	"fmt"
	"log"

	runespace "github.com/CryptoLabInc/runespace-sdk"
)

func main() {
	ctx := context.Background()

	// 1. Key set: generate once, then open wherever encrypt/decrypt is needed.
	keyOpts := []runespace.KeysOption{
		runespace.WithKeyPath("demo_keys"),
		runespace.WithKeyID("demo-key"),
		runespace.WithKeyDim(128), // must match the server's configured dim
	}
	if !runespace.KeysExist(keyOpts...) {
		if err := runespace.GenerateKeys(keyOpts...); err != nil {
			log.Fatal(err)
		}
	}
	keys, err := runespace.OpenKeys(keyOpts...)
	if err != nil {
		log.Fatal(err)
	}
	defer keys.Close()

	// 2. Connect over TLS (system cert pool).
	c, err := runespace.Dial("runespace.example:51024",
		runespace.WithAccessToken("..."))
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	// 3. Register the PUBLIC eval key, then operate. No load/unload step.
	if err := c.RegisterKeys(ctx, keys); err != nil {
		log.Fatal(err)
	}
	if err := c.Insert(ctx, "doc-1", []float32{0.1, 0.2 /* ...dim... */}); err != nil {
		log.Fatal(err)
	}
	hits, err := c.Search(ctx, []float32{0.1, 0.2 /* ...dim... */}, 10)
	if err != nil {
		log.Fatal(err)
	}
	for _, h := range hits {
		fmt.Printf("id=%s slot=%d score=%.4f\n", h.ID, h.Slot, h.Score)
	}
}
```

`Insert`/`Search` validate that the vector length equals `keys.Dim()`. The
engine returns scores by slot, not id; `Match.ID` is populated for items the
same client inserted (see `Match`).

Full API reference: <https://pkg.go.dev/github.com/CryptoLabInc/runespace-sdk>

## Examples

Runnable programs under `examples/` illustrate the common flows against a live
instance (configured via `RUNESPACE_ADDR` / `RUNESPACE_DIM` / `RUNESPACE_TOKEN` /
`RUNESPACE_KEYS`):

| Example | Flow |
| ------- | ---- |
| `examples/quickstart` | keygen → dial → register → insert → blind search |
| `examples/filtertags` | tagged insert, scoped search, and the `UpdateTags` / `RetagAll` / `RemoveTag` tag mutators |

```sh
RUNESPACE_ADDR=127.0.0.1:51024 RUNESPACE_DIM=128 go run ./examples/quickstart
```

The end-to-end **verification** suite that stands up a real server and asserts
crash/recovery/rebalance behavior lives in the `runespace` repo (`tests/`), next
to the engine it verifies — not here.

## Loading only the keys you need

`OpenKeys` materialises all three key parts (EncKey, EvalKey, SecKey) by
default. Pass `WithKeyParts(...)` to load a subset:

| Role | Parts | What works |
| ---- | ----- | ---------- |
| Encrypt + register (capture client) | `KeyPartEnc, KeyPartEval` | `EncryptFlat`/`EncryptClustered`, `RegisterKeys`, `Insert`, `Search` |
| Encrypt only (key already registered) | `KeyPartEnc` | `EncryptFlat`/`EncryptClustered`, `Insert`, `Search` |
| Decrypt only (console) | `KeyPartSec` | `DecryptResult` (Search result decode) |
| Default (all parts) | omit `WithKeyParts` | everything |

Calling an operation whose required part was not loaded returns
`ErrKeysNotForEncrypt`, `ErrKeysNotForDecrypt`, or `ErrKeysNotForRegister`.

## Building from source

```sh
git clone https://github.com/CryptoLabInc/runespace-sdk.git
cd runespace-sdk
make build
make test
```

| Target | Action |
| ------ | ------ |
| `make build` | `go build ./...` (includes the `examples/`) |
| `make test` | `go test ./...` |
| `make vet` | `go vet ./...` |
| `make fmt` | `gofmt -w .` |
| `make tidy` | `go mod tidy` |
| `make cover` | race-enabled coverage profile |

`CGO_ENABLED=1` is exported by the Makefile so cross-compile environments do
not silently produce a non-functional binary.

The RuneSpace protobuf/gRPC stubs under `pkg/runespacepb/` are vendored
(a verbatim hard copy from the `runespace` repo — see
`pkg/runespacepb/PROVENANCE`); there is no local proto-generation step.

## Refreshing the bundled libevi archives

See `third_party/evi/PROVENANCE` for the pinned evi-crypto revision and the
multi-platform refresh procedure.
