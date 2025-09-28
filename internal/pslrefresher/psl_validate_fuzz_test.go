package pslrefresher

import (
	"testing"
)

// FuzzPSLValidate feeds random byte slices into the validate function to ensure
// robust handling and absence of panics.
func FuzzPSLValidate(f *testing.F) {
	seed := []byte("// ===BEGIN ICANN DOMAINS===\ncom\nnet\n// ===END ICANN DOMAINS===\n")
	f.Add(seed)
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = validate(data)
	})
}
