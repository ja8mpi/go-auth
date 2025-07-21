package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestValidateJWT(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "test-secret"

	t.Run("valid token", func(t *testing.T) {
		token, err := MakeJWT(userID, tokenSecret, time.Hour)
		if err != nil {
			t.Fatalf("failed to create token: %v", err)
		}

		parsedUserID, err := ValidateJWT(token, tokenSecret)
		if err != nil {
			t.Fatalf("failed to validate token: %v", err)
		}

		if parsedUserID != userID {
			t.Errorf("expected userID %v, got %v", userID, parsedUserID)
		}
	})

	t.Run("invalid token string", func(t *testing.T) {
		_, err := ValidateJWT("invalid-token", tokenSecret)
		if err == nil {
			t.Error("expected error for invalid token")
		}
	})

	t.Run("wrong secret", func(t *testing.T) {
		token, err := MakeJWT(userID, tokenSecret, time.Hour)
		if err != nil {
			t.Fatalf("failed to create token: %v", err)
		}

		_, err = ValidateJWT(token, "wrong-secret")
		if err == nil {
			t.Error("expected error for wrong secret")
		}
	})

	t.Run("expired token", func(t *testing.T) {
		token, err := MakeJWT(userID, tokenSecret, -time.Hour)
		if err != nil {
			t.Fatalf("failed to create token: %v", err)
		}

		_, err = ValidateJWT(token, tokenSecret)
		if err == nil {
			t.Error("expected error for expired token")
		}
	})

	t.Run("empty token", func(t *testing.T) {
		_, err := ValidateJWT("", tokenSecret)
		if err == nil {
			t.Error("expected error for empty token")
		}
	})
}
