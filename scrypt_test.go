package scrypt

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Test cases
var (
	testLengths = []int{1, 8, 16, 32, 100, 500, 2500}
	password    = "super-secret-password"
)

var testParams = []struct {
	pass   bool
	params Params
}{
	{true, Params{16384, 8, 1, 32, 64}},
	{true, Params{16384, 8, 1, 16, 32}},
	{true, Params{65536, 8, 1, 16, 64}},
	{true, Params{1048576, 8, 2, 64, 128}},
	{false, Params{-1, 8, 1, 16, 32}},          // invalid N
	{false, Params{0, 8, 1, 16, 32}},           // invalid N
	{false, Params{1<<31 - 1, 8, 1, 16, 32}},   // invalid N
	{false, Params{16384, 0, 12, 16, 32}},      // invalid R
	{false, Params{16384, 8, 0, 16, 32}},       // invalid R > maxInt/128/P
	{false, Params{16384, 1 << 24, 1, 16, 32}}, // invalid R > maxInt/256
	{false, Params{1<<31 - 1, 8, 0, 16, 32}},   // invalid p < 0
	{false, Params{4096, 8, 1, 5, 32}},         // invalid SaltLen
	{false, Params{4096, 8, 1, 16, 2}},         // invalid DKLen
}

var testHashes = []struct {
	pass bool
	hash string
}{
	{false, "1$8$1$9003d0e8e69482843e6bd560c2c9cd94$1976f233124e0ee32bb2678eb1b0ed668eb66cff6fa43279d1e33f6e81af893b"},          // N too small
	{false, "$9003d0e8e69482843e6bd560c2c9cd94$1976f233124e0ee32bb2678eb1b0ed668eb66cff6fa43279d1e33f6e81af893b"},               // too short
	{false, "16384#8#1#18fbc325efa37402d27c3c2172900cbf$d4e5e1b9eedc1a6a14aad6624ab57b7b42ae75b9c9845fde32de765835f2aaf9"},      // incorrect separators
	{false, "16384$nogood$1$18fbc325efa37402d27c3c2172900cbf$d4e5e1b9eedc1a6a14aad6624ab57b7b42ae75b9c9845fde32de765835f2aaf9"}, // invalid R
	{false, "16384$8$abc1$18fbc325efa37402d27c3c2172900cbf$d4e5e1b9eedc1a6a14aad6624ab57b7b42ae75b9c9845fde32de765835f2aaf9"},   // invalid P
	{false, "16384$8$1$Tk9QRQ==$d4e5e1b9eedc1a6a14aad6624ab57b7b42ae75b9c9845fde32de765835f2aaf9"},                              // invalid salt (not hex)
	{false, "16384$8$1$18fbc325efa37402d27c3c2172900cbf$42ae====/75b9c9845fde32de765835f2aaf9"},                                 // invalid dk (not hex)
}

func TestGenerateRandomBytes(t *testing.T) {
	for _, v := range testLengths {
		_, err := GenerateRandomBytes(v)
		if err != nil {
			t.Fatalf("failed to generate random bytes")
		}
	}
}

func TestGenerateFromPassword(t *testing.T) {
	for _, v := range testParams {
		_, err := GenerateFromPassword([]byte(password), v.params)
		if v.pass && err != nil {
			t.Fatalf("unexpected error for valid params %+v: %v", v.params, err)
		}
		if !v.pass && err == nil {
			t.Fatalf("expected error for invalid params %+v, got nil", v.params)
		}
	}
}

func TestHashFormat(t *testing.T) {
	hash, err := GenerateFromPassword([]byte(password), DefaultParams)
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(string(hash), "$")
	if len(parts) != 5 {
		t.Fatalf("expected 5 dollar-separated fields, got %d: %s", len(parts), hash)
	}

	n, err := strconv.Atoi(parts[0])
	if err != nil || n != DefaultParams.N {
		t.Errorf("N field: got %q, want %d", parts[0], DefaultParams.N)
	}
	r, err := strconv.Atoi(parts[1])
	if err != nil || r != DefaultParams.R {
		t.Errorf("R field: got %q, want %d", parts[1], DefaultParams.R)
	}
	p, err := strconv.Atoi(parts[2])
	if err != nil || p != DefaultParams.P {
		t.Errorf("P field: got %q, want %d", parts[2], DefaultParams.P)
	}

	salt, err := hex.DecodeString(parts[3])
	if err != nil {
		t.Fatalf("salt is not valid hex: %v", err)
	}
	if len(salt) != DefaultParams.SaltLen {
		t.Errorf("salt length: got %d, want %d", len(salt), DefaultParams.SaltLen)
	}

	dk, err := hex.DecodeString(parts[4])
	if err != nil {
		t.Fatalf("dk is not valid hex: %v", err)
	}
	if len(dk) != DefaultParams.DKLen {
		t.Errorf("dk length: got %d, want %d", len(dk), DefaultParams.DKLen)
	}
}

func TestCompareHashAndPassword(t *testing.T) {
	hash, err := GenerateFromPassword([]byte(password), DefaultParams)
	if err != nil {
		t.Fatal(err)
	}

	if err := CompareHashAndPassword(hash, []byte(password)); err != nil {
		t.Fatal(err)
	}

	if err := CompareHashAndPassword(hash, []byte("invalid-password")); err == nil {
		t.Fatalf("mismatched passwords did not produce an error")
	}

	invalidHash := []byte("$166$$11$a2ad56a415af5")
	if err := CompareHashAndPassword(invalidHash, []byte(password)); err == nil {
		t.Fatalf("did not identify an invalid hash")
	}

	if err := CompareHashAndPassword(nil, []byte(password)); err == nil {
		t.Fatal("expected error for nil hash")
	}
	if err := CompareHashAndPassword([]byte{}, []byte(password)); err == nil {
		t.Fatal("expected error for empty hash")
	}
	if err := CompareHashAndPassword(hash, nil); err == nil {
		t.Fatal("expected error for nil password, got match")
	}
}

func TestCost(t *testing.T) {
	for _, want := range []Params{
		DefaultParams,
		{65536, 8, 1, 16, 64},
		{4096, 8, 1, 32, 32},
	} {
		hash, err := GenerateFromPassword([]byte(password), want)
		if err != nil {
			t.Fatalf("GenerateFromPassword(%+v): %v", want, err)
		}

		got, err := Cost(hash)
		if err != nil {
			t.Fatalf("Cost(%+v): %v", want, err)
		}

		if !reflect.DeepEqual(got, want) {
			t.Fatalf("cost mismatch: got %+v, want %+v", got, want)
		}
	}
}

func TestDecodeHash(t *testing.T) {
	for _, v := range testHashes {
		_, err := Cost([]byte(v.hash))
		if err == nil && v.pass == false {
			t.Fatal("invalid hash: did not correctly detect invalid password hash")
		}
	}
}

// TestKnownHash verifies CompareHashAndPassword against a hash constructed from
// the RFC 7914 Section 12 test vector (P="pleaseletmein", S="SodiumChloride",
// N=16384, r=8, p=1, dkLen=64). This catches regressions in the underlying
// scrypt implementation or changes to the hash encoding format.
func TestKnownHash(t *testing.T) {
	// salt = hex("SodiumChloride"), dk = RFC 7914 expected output
	known := []byte("16384$8$1$536f6469756d43686c6f72696465$" +
		"7023bdcb3afd7348461c06cd81fd38eb" +
		"fda8fbba904f8e3ea9b543f6545da1f2" +
		"d5432955613f0fcf62d49705242a9af9" +
		"e61e85dc0d651e40dfcf017b45575887")
	if err := CompareHashAndPassword(known, []byte("pleaseletmein")); err != nil {
		t.Fatalf("RFC 7914 known-good hash failed verification: %v", err)
	}

	if err := CompareHashAndPassword(known, []byte("wrong-password")); err == nil {
		t.Fatal("known hash matched incorrect password")
	}
}

func TestCheck(t *testing.T) {
	tests := []struct {
		pass   bool
		params Params
		desc   string
	}{
		{true, Params{2, 1, 1, 8, 16}, "minimum valid params"},
		{true, Params{16384, 8, 1, 16, 32}, "default params"},
		{false, Params{3, 8, 1, 16, 32}, "N not power of 2"},
		{false, Params{0, 8, 1, 16, 32}, "N is zero"},
		{false, Params{1, 8, 1, 16, 32}, "N is 1"},
		{false, Params{-1, 8, 1, 16, 32}, "N is negative"},
		{false, Params{16384, 0, 1, 16, 32}, "R is zero"},
		{false, Params{16384, 8, 0, 16, 32}, "P is zero"},
		{false, Params{16384, 8, 1, 7, 32}, "SaltLen below minimum"},
		{true, Params{16384, 8, 1, 8, 32}, "SaltLen at minimum"},
		{false, Params{16384, 8, 1, 16, 15}, "DKLen below minimum"},
		{true, Params{16384, 8, 1, 16, 16}, "DKLen at minimum"},
	}
	for _, tc := range tests {
		err := tc.params.Check()
		if tc.pass && err != nil {
			t.Errorf("%s: unexpected error: %v", tc.desc, err)
		}
		if !tc.pass && err == nil {
			t.Errorf("%s: expected error, got nil", tc.desc)
		}
	}
}

func TestCalibrate(t *testing.T) {
	timeout := 500 * time.Millisecond
	for testNum, tc := range []struct {
		MemMiB int
	}{
		{512},
		{256},
		{128},
		{64},
		{32},
		{16},
		{8},
		{1},
	} {
		var (
			p   Params
			err error
		)
		p, err = Calibrate(timeout, tc.MemMiB, p)
		if err != nil {
			t.Fatalf("%d. %#v: %v", testNum, p, err)
		}
		if (128*p.R*p.N)>>20 > tc.MemMiB {
			t.Errorf("%d. wanted memory limit %d, got %d.", testNum, tc.MemMiB, (128*p.R*p.N)>>20)
		}
		start := time.Now()
		_, err = GenerateFromPassword([]byte(password), p)
		dur := time.Since(start)
		t.Logf("GenerateFromPassword with %#v took %s (%v)", p, dur, err)
		if err != nil {
			t.Fatalf("%d. GenerateFromPassword with %#v: %v", testNum, p, err)
		}
		if dur < timeout/4 {
			t.Errorf("%d. GenerateFromPassword was too fast (expected at least %s, got %s) with %#v.", testNum, timeout/4, dur, p)
		} else if 3*timeout < dur {
			t.Errorf("%d. GenerateFromPassword took too long (expected at most %s, got %s) with %#v.", testNum, 3*timeout, dur, p)
		}
	}
}

func ExampleCalibrate() {
	p, err := Calibrate(1*time.Second, 128, Params{})
	if err != nil {
		panic(err)
	}
	dk, err := GenerateFromPassword([]byte("super-secret-password"), p)
	fmt.Printf("generated password is %q (%v)", dk, err)
}
