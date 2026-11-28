// Eviction decisions distinguish exhausted live capacity from an optional archive bound.

package audit

import "testing"

func TestEvictionHonorsRemainingBytes(t *testing.T) {
	t.Parallel()
	files := []RotatedFile{{Name: "oldest", Dir: "live", Bytes: 1}}
	for _, scenario := range []struct {
		remaining int64
		want      int
	}{
		{-1, 0},
		{0, 0},
		{1, -1},
	} {
		if got := oldestOver(files, "live", scenario.remaining); got != scenario.want {
			t.Errorf("remaining %d: selected %d, want %d", scenario.remaining, got, scenario.want)
		}
	}
}

func TestArchiveBudgetRetainsItsDisabledMode(t *testing.T) {
	t.Parallel()
	files := []RotatedFile{{Name: "oldest", Dir: "archive", Bytes: 2}}
	for _, scenario := range []struct {
		budget int64
		want   int
	}{
		{0, -1},
		{1, 0},
		{2, -1},
	} {
		r := archiver{dir: "archive", budget: scenario.budget}
		if got := r.overArchive(files, 0); got.at != scenario.want {
			t.Errorf("archive budget %d: selected %d, want %d", scenario.budget, got.at, scenario.want)
		}
	}
}
