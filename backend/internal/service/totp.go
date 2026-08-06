package service

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	totpDigits     = 6
	totpPeriodSecs = 30
	totpIssuer     = "DiviPay"
)

// GenerateTOTPSecret returns a new base32-encoded TOTP secret (RFC 6238, 160 bits).
func GenerateTOTPSecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

// TOTPCode computes the RFC 6238 TOTP code for the given secret and time.
func TOTPCode(secret string, t time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", err
	}

	counter := uint64(t.Unix() / totpPeriodSecs)
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(msg)
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		uint32(sum[offset+3])&0xff

	mod := uint32(1)
	for i := 0; i < totpDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, code%mod), nil
}

// ValidateTOTPCode verifies a code allowing a +/-1 step window for clock skew.
func ValidateTOTPCode(secret, code string) bool {
	if len(code) != totpDigits {
		return false
	}
	now := time.Now()
	for i := -1; i <= 1; i++ {
		candidate, err := TOTPCode(secret, now.Add(time.Duration(i)*totpPeriodSecs*time.Second))
		if err == nil && hmac.Equal([]byte(candidate), []byte(code)) {
			return true
		}
	}
	return false
}

// TOTPProvisioningURI builds the otpauth:// provisioning URI used for QR codes.
func TOTPProvisioningURI(secret, accountName string) string {
	u := url.URL{
		Scheme: "otpauth",
		Host:   "totp",
		Path:   "/" + totpIssuer + ":" + accountName,
	}
	q := u.Query()
	q.Set("secret", secret)
	q.Set("issuer", totpIssuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprintf("%d", totpDigits))
	q.Set("period", fmt.Sprintf("%d", totpPeriodSecs))
	u.RawQuery = q.Encode()
	return u.String()
}
