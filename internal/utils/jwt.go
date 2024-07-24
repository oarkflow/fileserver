package utils

import (
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// GenerateJWT Helper function to generate JWT token
func GenerateJWT(username string) (string, error) {
	claims := jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(time.Hour * 72).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(os.Getenv("JWT_SECRET")))
}
