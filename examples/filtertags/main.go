// Command filtertags shows opaque filter-tag visibility control: inserting items
// with per-item tags, scoping a search to a tag set, and the tag mutators — the
// per-item UpdateTags and the bulk RetagAll / RemoveTag.
//
// Tags are opaque visibility labels the engine never interprets: an item with no
// tags is public (survives every scope); a scoped search returns an item only if
// its tag set intersects the scope (or it is public).
//
// Same env as the quickstart example (RUNESPACE_ADDR/DIM/TOKEN/KEYS).
//
// Run:  go run ./examples/filtertags
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

	keyOpts := []runespace.KeysOption{
		runespace.WithKeyPath(keyDir),
		runespace.WithKeyID("example"),
		runespace.WithKeyDim(dim),
	}
	if err := runespace.GenerateKeys(keyOpts...); err != nil {
		log.Fatalf("GenerateKeys: %v", err)
	}
	keys, err := runespace.OpenKeys(keyOpts...)
	if err != nil {
		log.Fatalf("OpenKeys: %v", err)
	}
	defer keys.Close()

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
	if err := c.RegisterKeys(ctx, keys); err != nil {
		log.Fatalf("RegisterKeys: %v", err)
	}
	c.UseKeys(keys)

	// Insert two items tagged team1, one tagged team2, and one public (no tags).
	rng := rand.New(rand.NewSource(2))
	a, err := c.Insert(ctx, genVec(dim, rng), `{}`, runespace.WithFilterTags("team1"))
	if err != nil {
		log.Fatalf("insert a: %v", err)
	}
	b, err := c.Insert(ctx, genVec(dim, rng), `{}`, runespace.WithFilterTags("team1"))
	if err != nil {
		log.Fatalf("insert b: %v", err)
	}
	probe := genVec(dim, rng)
	if _, err := c.Insert(ctx, probe, `{}`, runespace.WithFilterTags("team2")); err != nil {
		log.Fatalf("insert c: %v", err)
	}

	// A team1-scoped search returns team1 (and public) items; team2 is excluded even
	// if it is the closest match.
	hits, err := c.Search(ctx, probe, 10, runespace.WithScope("team1"))
	if err != nil {
		log.Fatalf("scoped search: %v", err)
	}
	log.Printf("scope=team1 returned %d hits", len(hits))

	// Per-item retag: move item a from team1 to team2 (a removed tag stops matching
	// immediately server-side — memory-first).
	if err := c.UpdateTags(ctx, a, []string{"team2"}, []string{"team1"}); err != nil {
		log.Fatalf("UpdateTags: %v", err)
	}
	log.Printf("UpdateTags: moved %s team1 -> team2", a)

	// Bulk retag: move every remaining team1 carrier (item b) to team3 at once.
	n, err := c.RetagAll(ctx, "team1", "team3")
	if err != nil {
		log.Fatalf("RetagAll: %v", err)
	}
	log.Printf("RetagAll team1 -> team3 changed %d items (b=%s)", n, b)

	// Bulk remove: strip team2 from every carrier; those items become public.
	m, err := c.RemoveTag(ctx, "team2")
	if err != nil {
		log.Fatalf("RemoveTag: %v", err)
	}
	log.Printf("RemoveTag team2 changed %d items", m)
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
