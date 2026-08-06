package service

import (
	"testing"
	"time"
)

func TestTOTPCode_MatchesRFC6238Vector(t *testing.T) {
	// RFC 6238 test vectors: secret "12345678901234567890" (base32 = GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ)
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	vectors := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	}
	for _, v := range vectors {
		got, err := TOTPCode(secret, time.Unix(v.unix, 0).UTC())
		if err != nil {
			t.Fatalf("TOTPCode(%d): %v", v.unix, err)
		}
		if got != v.want {
			t.Errorf("TOTPCode(%d) = %s, want %s", v.unix, got, v.want)
		}
	}
}

func TestValidateTOTPCode_CurrentCode(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	code, err := TOTPCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !ValidateTOTPCode(secret, code) {
		t.Error("expected the current code to validate")
	}
	if ValidateTOTPCode(secret, "000000") {
		t.Error("expected an invalid code to be rejected")
	}
}

func TestTOTPProvisioningURI_IncludesSecret(t *testing.T) {
	uri := TOTPProvisioningURI("ABCDEFGH", "user@example.com")
	if uri[:8] != "otpauth:" {
		t.Errorf("unexpected scheme in uri: %s", uri)
	}
}
