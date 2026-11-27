// Tests Linux block-to-byte multiplication overflow saturation.

package disk

import (
	"math"
	"testing"
)

func TestMulBytesSaturatesOverflow(t *testing.T) {
	cases := []struct {
		name   string
		blocks uint64
		bsize  int64
		want   int64
	}{
		{name: "normal", blocks: 1024, bsize: 4096, want: 4194304},
		{name: "zero_bsize", blocks: 1024, bsize: 0, want: 0},
		{name: "negative_bsize", blocks: 1024, bsize: -4096, want: 0},
		{name: "overflow_int64", blocks: math.MaxInt64/4096 + 1, bsize: 4096, want: math.MaxInt64},
		{name: "overflow_uint64", blocks: math.MaxUint64, bsize: 4096, want: math.MaxInt64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mulBytes(tc.blocks, tc.bsize); got != tc.want {
				t.Fatalf("mulBytes(%d, %d) = %d, want %d", tc.blocks, tc.bsize, got, tc.want)
			}
		})
	}
}
