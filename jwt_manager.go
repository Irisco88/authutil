package authutil

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	commonpb "github.com/irisco88/protos/gen/common/v1"
	userpb "github.com/irisco88/protos/gen/user/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"time"
)

type authKey string
type TokenUserClaims struct {
	jwt.RegisteredClaims
	UserID    uint32            `json:"id"`
	UserName  string            `json:"un"`
	UserAgent string            `json:"ua"`
	IP        string            `json:"ip"`
	Email     string            `json:"em"`
	Role      commonpb.UserRole `json:"rl"`
}

type AuthManager struct {
	secretKey      string
	tokenValidTime time.Duration
	issuer         string
	signingMethod  jwt.SigningMethod
}

type AuthManagerInterface interface {
	VerifyToken(accessToken string) (*TokenUserClaims, error)
	GenerateNewToken(userInfo *userpb.User) (string, error)
}

var (
	ErrNotFoundToken                      = errors.New("not found token in metadata")
	_                AuthManagerInterface = &AuthManager{}
)

const ClaimKey authKey = "authKey"

func NewAuthManager(secretKey, issuer string, validTime time.Duration) *AuthManager {
	return &AuthManager{
		secretKey:      secretKey,
		tokenValidTime: validTime,
		issuer:         issuer,
		signingMethod:  jwt.SigningMethodHS256,
	}
}

func (am *AuthManager) GenerateNewToken(userInfo *userpb.User) (string, error) {
	userClaims := TokenUserClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    am.issuer,
			Subject:   userInfo.FirstName + " " + userInfo.LastName,
			ID:        uuid.New().String(),
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(am.tokenValidTime)),
			NotBefore: jwt.NewNumericDate(time.Now().UTC()),
		},
		Email:    userInfo.Email,
		UserID:   userInfo.Id,
		Role:     userInfo.Role,
		UserName: userInfo.UserName,
	}
	return am.generateToken(userClaims)
}

func (am *AuthManager) generateToken(claims TokenUserClaims) (string, error) {
	unsignedToken := jwt.NewWithClaims(am.signingMethod, claims)
	token, err := unsignedToken.SignedString([]byte(am.secretKey))
	if err != nil {
		return "", err
	}
	return token, nil
}

func (am *AuthManager) VerifyToken(accessToken string) (*TokenUserClaims, error) {
	token, err := jwt.ParseWithClaims(accessToken, &TokenUserClaims{}, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, fmt.Errorf("unexpected token signing method")
		}
		return []byte(am.secretKey), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*TokenUserClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}
	return claims, nil
}

func (am *AuthManager) ExtractContext(ctx context.Context) (*TokenUserClaims, error) {
	md, hasMd := metadata.FromIncomingContext(ctx)
	if !hasMd {
		return nil, status.Error(codes.Unauthenticated, "metadata is not provided")
	}
	values, found := md["token"]
	if !found || len(values) == 0 {
		return nil, ErrNotFoundToken
	}
	token := values[0]
	if len(token) == 0 {
		return nil, ErrNotFoundToken
	}
	return am.VerifyToken(token)
}

func TokenClaimsFromCtx(ctx context.Context) (*TokenUserClaims, bool) {
	claim, ok := ctx.Value(ClaimKey).(*TokenUserClaims)
	return claim, ok
}

func GenerateRandomSecretKey(len int) (string, error) {
	b := make([]byte, len)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%X", b), nil
}
