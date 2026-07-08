# All targets link the libevi cgo provider against the static archives
# bundled under third_party/evi/. Build prerequisites:
#   - C toolchain (cc/clang/gcc) on PATH
#   - OpenSSL 3 (libssl, libcrypto) — macOS: `brew install openssl@3`,
#     Debian/Ubuntu: `apt install libssl-dev`
# CGO_ENABLED=1 is set explicitly so cross-compile environments don't
# silently produce a non-functional binary.

.PHONY: build test test-e2e vet fmt tidy cover

export CGO_ENABLED=1

# `make test-e2e` talks to a live RuneSpace instance. RUNESPACE_ADDR is empty
# by default so the suite t.Skips; set it to run:
#   make test-e2e RUNESPACE_ADDR=runespace.example:51024 RUNESPACE_TOKEN=...
# RUNESPACE_DIM must match the server's configured dimension.
RUNESPACE_ADDR  ?=
RUNESPACE_TOKEN ?=
RUNESPACE_DIM   ?=
export RUNESPACE_ADDR RUNESPACE_TOKEN RUNESPACE_DIM

build:
	go build ./...

test:
	go test ./...

test-e2e:
	cd tests && go test -tags=e2e -timeout 10m -parallel 1 ./e2e/...

vet:
	go vet ./...

fmt:
	gofmt -w .

tidy:
	go mod tidy

cover:
	go test -race -coverprofile=coverage.txt -covermode=atomic ./...
