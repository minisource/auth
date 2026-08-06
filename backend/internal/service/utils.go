package service

import (
	"strings"
)

// MaskEmail masks email address for display
func MaskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return email
	}

	local := parts[0]
	domain := parts[1]

	if len(local) <= 2 {
		return local + "***@" + domain
	}

	masked := string(local[0]) + strings.Repeat("*", len(local)-2) + string(local[len(local)-1])
	return masked + "@" + domain
}

// MaskPhone masks phone number for display
func MaskPhone(phone string) string {
	if len(phone) < 4 {
		return phone
	}

	return phone[:3] + strings.Repeat("*", len(phone)-6) + phone[len(phone)-3:]
}
