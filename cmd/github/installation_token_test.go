package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestBearerTokenTransport_StampsHeader verifies that every request flowing
// through the transport gets the Authorization: Bearer <token> header,
// regardless of what the caller set.
func TestBearerTokenTransport_StampsHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	tr := &bearerTokenTransport{
		token: "ghs_installationtoken12345",
		next:  http.DefaultTransport,
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately set a wrong auth header; transport must overwrite it.
	req.Header.Set("Authorization", "Bearer wrong")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	resp.Body.Close()

	want := "Bearer ghs_installationtoken12345"
	if gotAuth != want {
		t.Errorf("Authorization = %q, want %q", gotAuth, want)
	}
}

// TestBearerTokenTransport_DoesNotMutateCaller verifies that the transport
// clones the request before stamping the header, so the caller's own
// request object is not modified (which would be a spooky side effect).
func TestBearerTokenTransport_DoesNotMutateCaller(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	tr := &bearerTokenTransport{
		token: "ghs_installationtoken12345",
		next:  http.DefaultTransport,
	}

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer original")

	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "Bearer original" {
		t.Errorf("caller's Authorization mutated: got %q, want %q", got, "Bearer original")
	}
}
