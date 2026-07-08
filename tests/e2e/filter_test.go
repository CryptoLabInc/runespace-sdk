//go:build e2e

package e2e

import (
	"context"
	"math/rand"
	"testing"
	"time"

	runespace "github.com/CryptoLabInc/runespace-sdk"
)

// TestE2E_FilterTagIsolation drives the filter-set (team-based) feature end to end
// through real FHE, on both flat modes (rmp + single, mode-agnostic fold):
//   - a scoped search excludes an out-of-scope item even when it is the closest match;
//   - a public item (no tags) survives every scope;
//   - no scope = filter off (everything visible);
//   - UpdateTags takes effect immediately — a removed tag stops matching (no leak), an
//     added one starts.
func TestE2E_FilterTagIsolation(t *testing.T) {
	for _, mode := range []string{"rmp", "single"} {
		t.Run(mode, func(t *testing.T) {
			s := newServer(t, serverOpts{nprobe: 8, flatMode: mode})
			s.start()
			s.register()
			s.waitReady(10 * time.Minute) // dim-sized key load can be slow

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			c := s.client(t)

			rng := rand.New(rand.NewSource(7))
			vA := genVec(s.dim, rng)
			vB := genVec(s.dim, rng)
			vPub := genVec(s.dim, rng)

			idA, err := c.Insert(ctx, vA, `{}`, runespace.WithFilterTags("team1"))
			if err != nil {
				t.Fatalf("insert A(team1): %v", err)
			}
			idB, err := c.Insert(ctx, vB, `{}`, runespace.WithFilterTags("team2"))
			if err != nil {
				t.Fatalf("insert B(team2): %v", err)
			}
			idPub, err := c.Insert(ctx, vPub, `{}`) // public: no tags
			if err != nil {
				t.Fatalf("insert Pub: %v", err)
			}

			// Query AT vB (B is the exact top match). With scope team1, B is excluded despite
			// being the closest hit; the public item still shows, and the team1 item does too.
			hits, err := c.Search(ctx, vB, 10, runespace.WithScope("team1"))
			if err != nil {
				t.Fatalf("search scope team1: %v", err)
			}
			if hitsContain(hits, idB) {
				t.Fatalf("team1 scope returned team2 item %s (LEAK): %s", idB, summarizeHits(hits))
			}
			if !hitsContain(hits, idPub) {
				t.Fatalf("team1 scope dropped public item %s: %s", idPub, summarizeHits(hits))
			}
			if !hitsContain(hits, idA) {
				t.Fatalf("team1 scope dropped team1 item %s: %s", idA, summarizeHits(hits))
			}

			// scope team2: B is visible and, being the query, the top hit.
			hits, err = c.Search(ctx, vB, 10, runespace.WithScope("team2"))
			if err != nil {
				t.Fatalf("search scope team2: %v", err)
			}
			if len(hits) == 0 || hits[0].ID != idB {
				t.Fatalf("team2 scope top = %s; want %s", summarizeHits(hits), idB)
			}

			// no scope: filter off, B visible.
			hits, err = c.Search(ctx, vB, 10)
			if err != nil {
				t.Fatalf("search no scope: %v", err)
			}
			if !hitsContain(hits, idB) {
				t.Fatalf("no-scope search dropped %s: %s", idB, summarizeHits(hits))
			}

			// UpdateTags: move A from team1 to team2. Immediately a team1 search no longer
			// sees A (removed tag stops matching — no lag/leak), and a team2 search does.
			if err := c.UpdateTags(ctx, idA, []string{"team2"}, []string{"team1"}); err != nil {
				t.Fatalf("UpdateTags A: %v", err)
			}
			hits, err = c.Search(ctx, vA, 10, runespace.WithScope("team1"))
			if err != nil {
				t.Fatalf("search vA scope team1 after retag: %v", err)
			}
			if hitsContain(hits, idA) {
				t.Fatalf("after retag, team1 scope still returns A %s (REMOVE LAG/LEAK): %s", idA, summarizeHits(hits))
			}
			hits, err = c.Search(ctx, vA, 10, runespace.WithScope("team2"))
			if err != nil {
				t.Fatalf("search vA scope team2 after retag: %v", err)
			}
			if !hitsContain(hits, idA) {
				t.Fatalf("after retag, team2 scope missing A %s: %s", idA, summarizeHits(hits))
			}
		})
	}
}

func hitsContain(hits []runespace.Match, id string) bool {
	for _, h := range hits {
		if h.ID == id {
			return true
		}
	}
	return false
}
