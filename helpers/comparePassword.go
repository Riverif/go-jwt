package helpers

import (
	"golang.org/x/crypto/bcrypt"
)

// ComparePassword compares a hashed password with a plain text password
func ComparePassword(hashedPassword, password string) error {
    return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}