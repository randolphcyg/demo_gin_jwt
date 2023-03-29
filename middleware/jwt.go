package middleware

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
)

const (
	TokenSecret     = "**挪威的森林**"    // jwt secret
	ServiceName     = "demo_gin_jwt" // service name
	TokenExpireTime = 60 * 60 * 24   // expiring time
)

var (
	ErrTokenMalformed   = errors.New("that's not even a token")
	ErrTokenExpired     = errors.New("token is expired")
	ErrTokenNotValidYet = errors.New("token not active yet")
	ErrTokenOther       = errors.New("couldn't handle this token")
)

// JWT JWT对象
type JWT struct {
	SigningKey []byte
}

// CustomClaims Custom Claims
type CustomClaims struct {
	Username string
	jwt.RegisteredClaims
}

// NewJWT New JWT objects
func NewJWT() *JWT {
	return &JWT{
		[]byte(TokenSecret),
	}
}

// NewToken New Token
func (j *JWT) NewToken(username string) (tokenString string, err error) {
	claim := CustomClaims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			Audience:  jwt.ClaimStrings{ServiceName},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(TokenExpireTime * time.Second)), // expiring time
			IssuedAt:  jwt.NewNumericDate(time.Now()),                                    // signing time
			NotBefore: jwt.NewNumericDate(time.Now()),                                    // Effective time
			ID:        username,
		}}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim) // Use the HS256 algorithm
	tokenString, err = token.SignedString(j.SigningKey)

	return tokenString, err
}

// ParseToken Parse Token
func (j *JWT) ParseToken(tokenString string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return j.SigningKey, nil
	})
	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorMalformed != 0 {
				return nil, ErrTokenMalformed
			} else if ve.Errors&jwt.ValidationErrorExpired != 0 {
				return nil, ErrTokenExpired
			} else if ve.Errors&jwt.ValidationErrorNotValidYet != 0 {
				return nil, ErrTokenNotValidYet
			} else {
				return nil, ErrTokenOther
			}
		}
	}
	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, ErrTokenOther
}

func JWTAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.Request.Header.Get("token")
		if token == "" {
			c.JSON(http.StatusOK, gin.H{
				"status": -1,
				"msg":    "请求未携带token，无权限访问",
				"data":   nil,
			})
			c.Abort()
			return
		}

		j := NewJWT()
		_, err := j.ParseToken(token)
		if err != nil {
			// token expire
			if errors.Is(err, ErrTokenExpired) {
				c.JSON(http.StatusOK, gin.H{
					"status": -1,
					"msg":    ErrTokenExpired.Error(),
					"data":   nil,
				})
				c.Abort()
				return
			}

			// other error
			c.JSON(http.StatusOK, gin.H{
				"status": -1,
				"msg":    err.Error(),
				"data":   nil,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
