package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}
func CheckPasswordHash(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	claims := jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiresIn)),
		Subject:   userID.String(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(tokenSecret))
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	fmt.Println(">>> go-auth ValidateJWT called")
	claims := &jwt.RegisteredClaims{}
	token, parseErr := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(tokenSecret), nil
	})
	fmt.Println("JWT Subject:", claims.Subject)

	userID, uuidErr := uuid.Parse(claims.Subject)
	if uuidErr != nil {
		return uuid.UUID{}, fmt.Errorf("invalid subject UUID: %w", uuidErr)
	}

	if parseErr != nil {
		return uuid.UUID{}, fmt.Errorf("invalid token: %w", parseErr)
	}

	if !token.Valid {
		return uuid.UUID{}, fmt.Errorf("token is not valid")
	}

	return userID, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	token := headers.Get("Authorization")
	if token == "" {
		return "", errors.New("no auth header found")
	}

	return strings.TrimPrefix(token, "Bearer "), nil
}
