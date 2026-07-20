// Command quickstart shows the RuneSpace SDK end-to-end basic flow: generate a
// local key set, dial an instance, register the PUBLIC eval keys, insert an
// encrypted vector, and run a blind search that decrypts and ranks client-side.
//
// It talks to a live instance; configure via env:
//
//	RUNESPACE_ADDR   host:port (default 127.0.0.1:51024)
//	RUNESPACE_DIM    embedding dimension, must match the instance (default 128)
//	RUNESPACE_TOKEN  bearer token (optional)
//	RUNESPACE_KEYS   local key directory (default ./rs-keys)
//
// Run:  go run ./examples/quickstart
package main

import (
	"context"
	"log"
	"math"
	"math/rand"
	"os"
	"strconv"
	"time"

	runespace "github.com/CryptoLabInc/runespace-sdk"
)

func main() {
	addr := envOr("RUNESPACE_ADDR", "127.0.0.1:51024")
	dim := envInt("RUNESPACE_DIM", 128)
	keyDir := envOr("RUNESPACE_KEYS", "./rs-keys")

	// 1. Generate the client key set once (secret key stays local; only the PUBLIC
	//    eval key is ever uploaded), then open it for encrypt/decrypt.
	keyOpts := []runespace.KeysOption{
		runespace.WithKeyPath(keyDir),
		runespace.WithKeyID("example"),
		runespace.WithKeyDim(dim),
	}
	if !runespace.KeysExist(keyOpts...) {
		if err := runespace.GenerateKeys(keyOpts...); err != nil {
			log.Fatalf("GenerateKeys: %v", err)
		}
	}
	keys, err := runespace.OpenKeys(keyOpts...)
	if err != nil {
		log.Fatalf("OpenKeys: %v", err)
	}
	defer keys.Close()

	// 2. Dial the instance (WithInsecure for a local, non-TLS endpoint).
	dialOpts := []runespace.ClientOption{runespace.WithInsecure()}
	if tok := os.Getenv("RUNESPACE_TOKEN"); tok != "" {
		dialOpts = append(dialOpts, runespace.WithAccessToken(tok))
	}
	c, err := runespace.Dial(addr, dialOpts...)
	if err != nil {
		log.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	if info, err := c.Info(ctx); err != nil {
		log.Fatalf("Info: %v", err)
	} else {
		log.Printf("connected: engine=%s ready=%v", info.EngineStatus, info.Ready)
	}

	// 3. Register the PUBLIC eval keys, then bind them to the client for crypto.
	if err := c.RegisterKeys(ctx, keys); err != nil {
		log.Fatalf("RegisterKeys: %v", err)
	}
	c.UseKeys(keys)

	// 4. Insert an encrypted vector (the SDK encrypts locally, then Insert).
	rng := rand.New(rand.NewSource(1))
	v := genVec(dim, rng)
	id, err := c.Insert(ctx, v, `{"title":"hello"}`)
	if err != nil {
		log.Fatalf("Insert: %v", err)
	}
	log.Printf("inserted id=%s", id)

	// 5. Search: send the query vector under the current PCMM contract; the
	//    server encodes it, evaluates against ciphertext items, and returns
	//    encrypted scores for client-side decryption and ranking.
	hits, err := c.Search(ctx, v, 5)
	if err != nil {
		log.Fatalf("Search: %v", err)
	}
	for i, h := range hits {
		log.Printf("#%d id=%s score=%.4f meta=%s", i, h.ID, h.Score, h.Metadata)
	}
}

func genVec(dim int, rng *rand.Rand) []float32 {
	v := make([]float32, dim)
	var norm float64
	for i := range v {
		x := rng.NormFloat64()
		v[i] = float32(x)
		norm += x * x
	}
	if norm = math.Sqrt(norm); norm == 0 {
		norm = 1
	}
	for i := range v {
		v[i] = float32(float64(v[i]) / norm)
	}
	return v
}

func envOr(key, def string) string {
	if s := os.Getenv(key); s != "" {
		return s
	}
	return def
}

func envInt(key string, def int) int {
	if s := os.Getenv(key); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return n
		}
	}
	return def
}
