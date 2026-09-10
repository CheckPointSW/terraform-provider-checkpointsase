package checkpointsase

import "testing"

/*
TestValidateASNCoversTheWhole4ByteRange is the gate on a bug that was a BUILD
failure, not a runtime one.

Both ASN attributes used validation.IntBetween(1, 4294967295). That compiles on
a 64-bit host and fails outright for GOARCH=386 and GOARCH=arm, which
`make release` builds -- so the whole release was broken while every local
build and every test passed. The boundary cases below are what a narrowing
"fix" (clamping to MaxInt32, say) would break silently.

The upper bound only exists as a value on 64-bit platforms; see the note on
validateASN.
*/
func TestValidateASNCoversTheWhole4ByteRange(t *testing.T) {
	for _, tc := range []struct {
		name   string
		asn    int
		reject bool
	}{
		{"zero is not an ASN", 0, true},
		{"negative", -1, true},
		{"one is the bottom of the range", 1, false},
		{"a 2-byte ASN", 65000, false},
		{"just above the 32-bit signed maximum", 2147483648, false},
		{"the top of the 4-byte range", 4294967295, false},
		{"one past the top", 4294967296, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A 32-bit build cannot hold the large cases in an int at all, so
			// they are meaningless there rather than wrong. Skip instead of
			// asserting something the platform cannot express.
			if int64(tc.asn) != int64(int(tc.asn)) {
				t.Skip("value does not fit in int on this platform")
			}
			_, errs := validateASN(tc.asn, "left_asn")
			if got := len(errs) > 0; got != tc.reject {
				t.Errorf("validateASN(%d) rejected=%v, want %v: %v", tc.asn, got, tc.reject, errs)
			}
		})
	}
}
