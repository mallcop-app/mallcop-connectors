package main

import (
	"strings"
	"testing"
)

func TestCursorRoundtrip(t *testing.T) {
	key := sigKey(12345, 67890)
	raw := "Y3Vyc29yMTIzNDU2"

	encoded := encodeCursor(raw, key)
	if encoded == "" {
		t.Fatal("encodeCursor returned empty string")
	}

	decoded, err := decodeCursor(encoded, key)
	if err != nil {
		t.Fatalf("decodeCursor: %v", err)
	}
	if decoded != raw {
		t.Errorf("roundtrip mismatch: got %q, want %q", decoded, raw)
	}
}

func TestCursorTamperDetection(t *testing.T) {
	key := sigKey(12345, 67890)
	raw := "original-cursor-value"

	encoded := encodeCursor(raw, key)

	// Tamper with the payload (flip a char in the base64 part before the dot).
	parts := strings.SplitN(encoded, ".", 2)
	if len(parts) != 2 {
		t.Fatal("encoded cursor has no dot separator")
	}
	// Flip the last char of the payload.
	payload := []byte(parts[0])
	payload[len(payload)-1] ^= 0x01
	tampered := string(payload) + "." + parts[1]

	_, err := decodeCursor(tampered, key)
	if err == nil {
		t.Fatal("expected error for tampered cursor, got nil")
	}
	if !strings.Contains(err.Error(), "signature mismatch") && !strings.Contains(err.Error(), "tampered") && !strings.Contains(err.Error(), "invalid cursor") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestCursorTamperSignature(t *testing.T) {
	key := sigKey(12345, 67890)
	raw := "another-cursor"

	encoded := encodeCursor(raw, key)
	// Tamper with the signature part.
	parts := strings.SplitN(encoded, ".", 2)
	sig := []byte(parts[1])
	sig[0] ^= 0xFF
	tampered := parts[0] + "." + string(sig)

	_, err := decodeCursor(tampered, key)
	if err == nil {
		t.Fatal("expected error for tampered signature, got nil")
	}
}

func TestCursorWrongKey(t *testing.T) {
	key1 := sigKey(1111, 2222)
	key2 := sigKey(3333, 4444)
	raw := "cursor-value"

	encoded := encodeCursor(raw, key1)
	_, err := decodeCursor(encoded, key2)
	if err == nil {
		t.Fatal("expected error decoding cursor with wrong key, got nil")
	}
}

func TestCursorMissingDot(t *testing.T) {
	_, err := decodeCursor("nodothere", sigKey(1, 2))
	if err == nil {
		t.Fatal("expected error for cursor without dot separator")
	}
}

func TestValidateCursorInvalidChars(t *testing.T) {
	cases := []struct {
		name   string
		cursor string
	}{
		{"newline", "abc\ndef"},
		{"null byte", "abc\x00def"},
		{"space", "abc def"},
		{"too long", strings.Repeat("a", cursorMaxLen+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCursor(tc.cursor)
			if err == nil {
				t.Errorf("validateCursor(%q): expected error, got nil", tc.cursor)
			}
		})
	}
}

func TestValidateCursorValid(t *testing.T) {
	valid := []string{
		"abc123",
		"abc+def/ghi=",
		"abc_def-ghi",
		"Y3Vyc29yMTIzNDU2",
	}
	for _, c := range valid {
		if err := validateCursor(c); err != nil {
			t.Errorf("validateCursor(%q): unexpected error: %v", c, err)
		}
	}
}
