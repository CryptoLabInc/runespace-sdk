# runespace-sdk e2e tests

Black-box integration suite, isolated as a separate Go module with
`replace github.com/CryptoLabInc/runespace-sdk => ../` so the tests can
only touch the public API surface (reaching into `internal/` fails to resolve
at compile time).

Every file carries `//go:build e2e`, which keeps the suite out of
`go build ./...` for consumers. Each scenario `t.Skip`s when `RUNESPACE_ADDR`
is unset, so a missing endpoint never red-flags CI.

## Running

From the repo root, against a TLS instance:

```sh
make test-e2e RUNESPACE_ADDR=runespace.example:51024 RUNESPACE_TOKEN=<bearer>
```

A working cgo toolchain is required — the suite generates an evi key set
locally before talking to the server.

## Environment variables

| Name                 | Meaning                                                          |
| -------------------- | ---------------------------------------------------------------- |
| `RUNESPACE_ADDR`     | `host:port`. Empty → every scenario `t.Skip`s.                   |
| `RUNESPACE_TOKEN`    | Bearer token; sent as `authorization: Bearer ...` (optional).    |
| `RUNESPACE_DIM`      | Embedding dimension; must match the server's config. Default 128.|

## Scenarios

| Test                   | What it verifies                                                                 |
| ---------------------- | -------------------------------------------------------------------------------- |
| `TestE2E_Info`         | TLS/auth handshake + GetInfo round-trips; engine reports `status == "ok"`.       |
| `TestE2E_InsertSearch` | Generate keys → RegisterKeys → Insert one-hot vectors → Search ranks the matching id first → Delete. |
