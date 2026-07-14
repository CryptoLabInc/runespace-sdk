# All targets link the libevi cgo provider against the static archives
# bundled under third_party/evi/. Build prerequisites:
#   - C toolchain (cc/clang/gcc) on PATH
#   - OpenSSL 3 (libssl, libcrypto) — macOS: `brew install openssl@3`,
#     Debian/Ubuntu: `apt install libssl-dev`
# CGO_ENABLED=1 is set explicitly so cross-compile environments don't
# silently produce a non-functional binary.

.PHONY: build test vet fmt tidy cover

export CGO_ENABLED=1

# The end-to-end verification suite that drives a live server lives in the
# runespace repo (tests/), next to the engine it verifies. This repo ships the
# public client plus runnable usage examples under examples/ (built by `build`).

build:
	go build ./...

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

tidy:
	go mod tidy

cover:
	go test -race -coverprofile=coverage.txt -covermode=atomic ./...
