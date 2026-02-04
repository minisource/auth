package service

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/minisource/auth/config"
	"github.com/minisource/go-common/common"
	"golang.org/x/crypto/bcrypt"
)

// PasswordService handles password operations
type PasswordService struct {
	cfg *config.PasswordConfig
}

func NewPasswordService(cfg *config.PasswordConfig) *PasswordService {
	return &PasswordService{cfg: cfg}
}

// HashPassword hashes a password using bcrypt
func (s *PasswordService) HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// VerifyPassword checks if a password matches a hash
func (s *PasswordService) VerifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// ValidatePassword validates password against configured rules
func (s *PasswordService) ValidatePassword(password string) error {
	if len(password) < s.cfg.MinLength {
		return ErrPasswordTooWeak
	}

	if s.cfg.RequireUppercase && !hasUppercase(password) {
		return ErrPasswordTooWeak
	}

	if s.cfg.RequireLowercase && !hasLowercase(password) {
		return ErrPasswordTooWeak
	}

	if s.cfg.RequireNumber && !hasNumber(password) {
		return ErrPasswordTooWeak
	}

	if s.cfg.RequireSpecial && !hasSpecial(password) {
		return ErrPasswordTooWeak
	}

	return nil
}

// GetPasswordStrength returns password strength as a value from 0-4
func (s *PasswordService) GetPasswordStrength(password string) int {
	strength := 0

	if len(password) >= 8 {
		strength++
	}
	if len(password) >= 12 {
		strength++
	}
	if hasUppercase(password) && hasLowercase(password) {
		strength++
	}
	if hasNumber(password) {
		strength++
	}
	if hasSpecial(password) {
		strength++
	}

	if strength > 4 {
		strength = 4
	}

	return strength
}

func hasUppercase(s string) bool {
	for _, r := range s {
		if unicode.IsUpper(r) {
			return true
		}
	}
	return false
}

func hasLowercase(s string) bool {
	for _, r := range s {
		if unicode.IsLower(r) {
			return true
		}
	}
	return false
}

func hasNumber(s string) bool {
	for _, r := range s {
		if unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

func hasSpecial(s string) bool {
	specialChars := "!@#$%^&*()_+-=[]{}|;':\",./<>?"
	for _, r := range s {
		if strings.ContainsRune(specialChars, r) {
			return true
		}
	}
	return false
}

// ValidateEmail validates email format
func ValidateEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

// ValidatePhone validates Iranian mobile phone number format
func ValidatePhone(phone string) bool {
	return common.ValidateIranMobileNumber(phone)
}

// NormalizePhone normalizes phone number to E.164 format (+989123456789)
// Accepts: +989011793041, 09011793041, 9011793041
func NormalizePhone(phone string) string {
	return common.NormalizeIranPhone(phone)
}

// NormalizeEmail normalizes email address
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
