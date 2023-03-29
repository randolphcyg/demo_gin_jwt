package controller

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/randolphcyg/demo_gin_jwt/middleware"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func Login(c *gin.Context) {
	var u User
	if err := c.BindJSON(&u); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status": -1,
			"msg":    "User data parsing failed:" + err.Error(),
			"data":   nil,
		})
	}

	isPass, err := LoginVerify(u) // Login logic verification(database)
	if !isPass {
		c.JSON(http.StatusOK, gin.H{
			"status": -1,
			"msg":    "Validation failed:" + err.Error(),
			"data":   nil,
		})

	}

	genToken(c, u) // Validation passed, new token
}

// LoginVerify fake login info database verification
func LoginVerify(u User) (bool, error) {
	fmt.Println(u.Username + " login!")

	return true, nil
}

// genToken generate token for user
func genToken(c *gin.Context, user User) {
	j := middleware.NewJWT()
	tokenString, err := j.NewToken(user.Username)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status": -1,
			"msg":    err.Error(),
			"data":   nil,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"status": 0,
		"msg":    "login success",
		"data": struct {
			Username string
			Token    string
		}{
			Username: user.Username,
			Token:    tokenString,
		},
	})

	return
}

// Write secure
func Write(ctx *gin.Context) {
	tokenString := ctx.Request.Header.Get("token")
	j := middleware.NewJWT()
	claims, err := j.ParseToken(tokenString)
	if err != nil {
		ctx.JSON(http.StatusOK, gin.H{
			"status": -1,
			"msg":    err.Error(),
			"data":   nil,
		})
	}

	if claims != nil {
		ctx.JSON(http.StatusOK, gin.H{
			"status": 0,
			"msg":    "The token is valid",
			"data":   claims,
		})
	}
}

// Read insecure
func Read(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, gin.H{
		"status": 0,
		"msg":    "read success! token is not necessary",
		"data":   nil,
	})
}
