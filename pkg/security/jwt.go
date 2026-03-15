package security

import (
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
