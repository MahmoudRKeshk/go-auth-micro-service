package security

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

type JwtService struct {
	jwtSecret string
}

func NewJwtService(secret string) *JwtService {
	return &JwtService{
		jwtSecret: secret,
	}
}

func (s *JwtService) GenerateToken(userId, userRole string, expiryTime time.Time) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userId":   userId,
		"userRole": userRole,
		"exp":      expiryTime.Unix(),
	})

	return token.SignedString([]byte(s.jwtSecret))
}

func (s *JwtService) ParseToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(s.jwtSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	return claims, nil
}
