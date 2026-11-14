package recovery

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

// cheap keeps the tests fast; DefaultParams are covered by TestDefaultParams.
var cheap = Params{Memory: minMemory, Time: 1, Threads: 1}

const fpr = "0CBF4CAA80A81A887EBBE33E2ED3004C145B215F"

func seal(t *testing.T, password, plaintext string) []byte {
	t.Helper()
	blob, err := SealWith(cheap, []byte(password), fpr, []byte(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

func TestRoundTrip(t *testing.T) {
	blob := seal(t, "correct horse battery staple", "-----BEGIN PGP PRIVATE KEY BLOCK-----")
	if bytes.Contains(blob, []byte("PRIVATE KEY")) {
		t.Fatal("plaintext leaked into the sealed file")
	}
	plaintext, fingerprint, err := Open([]byte("correct horse battery staple"), blob)
	if err != nil || string(plaintext) != "-----BEGIN PGP PRIVATE KEY BLOCK-----" || fingerprint != fpr {
		t.Fatalf("Open() = %q, %q, %v", plaintext, fingerprint, err)
	}
}

func TestSealIsRandomized(t *testing.T) {
	if bytes.Equal(seal(t, "pw", "same"), seal(t, "pw", "same")) {
		t.Fatal("two seals of the same input are identical")
	}
}

func TestWrongPassword(t *testing.T) {
	blob := seal(t, "right", "secret")
	if _, _, err := Open([]byte("wrong"), blob); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("Open(wrong) = %v; want ErrWrongPassword", err)
	}
	if _, _, err := Open(nil, blob); err == nil {
		t.Fatal("Open(empty password) succeeded")
	}
}

func edit(t *testing.T, blob []byte, change func(map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(blob, &m); err != nil {
		t.Fatal(err)
	}
	change(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestTamperedHeaderOrCiphertextFails(t *testing.T) {
	blob := seal(t, "pw", "secret")
	// A valid but different fingerprint must not be accepted: the header is authenticated.
	other := edit(t, blob, func(m map[string]any) { m["fpr"] = "1111111111111111111111111111111111111111" })
	if _, _, err := Open([]byte("pw"), other); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("tampered fingerprint: %v", err)
	}
	var f file
	json.Unmarshal(blob, &f)
	f.Ciphertext[0] ^= 1
	flipped, _ := json.Marshal(f)
	if _, _, err := Open([]byte("pw"), flipped); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("tampered ciphertext: %v", err)
	}
}

func TestHostileParametersRejectedBeforeDerivation(t *testing.T) {
	blob := seal(t, "pw", "secret")
	cases := map[string]func(map[string]any){
		"huge memory":  func(m map[string]any) { m["m"] = 64 * 1024 * 1024 },
		"tiny memory":  func(m map[string]any) { m["m"] = 1 },
		"many passes":  func(m map[string]any) { m["t"] = 1000 },
		"zero threads": func(m map[string]any) { m["p"] = 0 },
		"version":      func(m map[string]any) { m["v"] = 2 },
		"kdf":          func(m map[string]any) { m["kdf"] = "scrypt" },
		"short salt":   func(m map[string]any) { m["salt"] = "AAAA" },
		"fingerprint":  func(m map[string]any) { m["fpr"] = "not-a-fingerprint" },
	}
	for name, change := range cases {
		_, _, err := Open([]byte("pw"), edit(t, blob, change))
		if err == nil || errors.Is(err, ErrWrongPassword) {
			t.Errorf("%s: Open() = %v; want a validation error", name, err)
		}
	}
	if _, _, err := Open([]byte("pw"), []byte("not json")); err == nil {
		t.Error("garbage accepted")
	}
	if _, _, err := Open([]byte("pw"), make([]byte, maxSize+1)); err == nil {
		t.Error("oversized file accepted")
	}
}

func TestSealRejectsBadInput(t *testing.T) {
	if _, err := SealWith(cheap, nil, fpr, []byte("x")); err == nil {
		t.Error("empty password accepted")
	}
	if _, err := SealWith(cheap, []byte("pw"), "abc", []byte("x")); err == nil {
		t.Error("invalid fingerprint accepted")
	}
	if _, err := SealWith(Params{Memory: maxMemory * 2, Time: 1, Threads: 1}, []byte("pw"), fpr, []byte("x")); err == nil {
		t.Error("out-of-range costs accepted")
	}
}

func TestDefaultParams(t *testing.T) {
	if testing.Short() {
		t.Skip("derives a 256 MiB key")
	}
	blob, err := Seal([]byte("pw"), fpr, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	var f file
	json.Unmarshal(blob, &f)
	if f.Memory != 256*1024 || f.Time != 3 || f.Threads != 4 {
		t.Fatalf("default costs = %d/%d/%d", f.Memory, f.Time, f.Threads)
	}
	if plaintext, _, err := Open([]byte("pw"), blob); err != nil || string(plaintext) != "secret" {
		t.Fatalf("Open() = %q, %v", plaintext, err)
	}
}
