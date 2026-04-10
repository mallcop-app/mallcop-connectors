package mallcopconnectors_test

import "testing"

func TestHello(t *testing.T) {
	got := "mallcop-connectors"
	if got == "" {
		t.Fatal("expected non-empty module name")
	}
}
