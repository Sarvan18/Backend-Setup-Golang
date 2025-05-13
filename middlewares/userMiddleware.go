package user_middlewares

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/mail"
	"os"
	"strings"
	"time"
	"unicode"

	user_model "github.com/Sarvan18/Backend-Setup-Golang.git/golang-Backend-Setup/models"
	handleError "github.com/Sarvan18/Backend-Setup-Golang.git/golang-Backend-Setup/utils"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

var User *user_model.User

func RegisterUserMiddleware() gin.HandlerFunc {
	caughtedErrors := []handleError.ErrorWithCode{}
	return func(c *gin.Context) {
		c.Header("Content-Type", "application/json")

		if c.Request.Method != "POST" {
			errMessage, _ := json.Marshal(fmt.Sprintf("invalid Method : %v", c.Request.Method))
			c.JSON(http.StatusInternalServerError, gin.H{"error": errMessage})
		}

		defer c.Request.Body.Close()

		if err := c.Request.ParseForm(); err != nil {
			errJson, _ := json.Marshal(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": errJson})

		}

		User = &user_model.User{
			Name:            c.Request.FormValue("name"),
			Email:           c.Request.FormValue("email"),
			Gender:          c.Request.FormValue("gener"),
			Password:        c.Request.FormValue("password"),
			ConfirmPassword: c.Request.FormValue("confirmpassword"),
		}

		if strings.TrimSpace(string(User.Name)) == "" {
			caughtedErrors = append(caughtedErrors, handleError.ErrorWithCode{Error: "Name Can't be Empty", StatusCode: http.StatusPartialContent})
		}

		if strings.TrimSpace(string(User.Email)) == "" {
			caughtedErrors = append(caughtedErrors, handleError.ErrorWithCode{Error: "Name Can't be Empty", StatusCode: http.StatusPartialContent})
		}

		_, err := mail.ParseAddress(User.Email)

		if err != nil {
			caughtedErrors = append(caughtedErrors, handleError.ErrorWithCode{Error: err.Error(), StatusCode: http.StatusBadRequest})
		}

		if strings.TrimSpace(string(User.Gender)) == "" || strings.TrimSpace(string(User.Gender)) != "Male" || strings.TrimSpace(string(User.Gender)) != "Female" || strings.TrimSpace(string(User.Gender)) != "Transgender" {
			caughtedErrors = append(caughtedErrors, handleError.ErrorWithCode{Error: "Can't be Empty Or Invalid Gender", StatusCode: http.StatusPartialContent})
		}

		if strings.TrimSpace(string(User.Password)) == "" {
			caughtedErrors = append(caughtedErrors, handleError.ErrorWithCode{Error: "Password Can't be Empty", StatusCode: http.StatusPartialContent})
		}

		hasNum, hasUpper, hasSpecial := validatePassword(User.Password)

		if !hasNum || !hasUpper || !hasSpecial {
			caughtedErrors = append(caughtedErrors, handleError.ErrorWithCode{Error: fmt.Sprintf("Password Missing Field. hasNum : %v , hasUpper : %v , hasSpecial : %v", hasNum, hasUpper, hasSpecial), StatusCode: http.StatusPartialContent})
		}

		if User.Password == User.ConfirmPassword {
			caughtedErrors = append(caughtedErrors, handleError.ErrorWithCode{Error: "Password Not Matches", StatusCode: http.StatusPartialContent})
		}

		if len(caughtedErrors) != 0 {
			byteError, _ := json.Marshal(caughtedErrors)
			c.Data(http.StatusBadRequest, "application/octet-stream", byteError)
			caughtedErrors = nil
			return
		}

		c.Next()
	}

}

func UserLoginMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Content-Type", "application/json")
		if c.Request.Method != "POST" {
			err := handleError.ErrorWithCode{Error: fmt.Sprintf("invalid Method %v", c.Request.Method),
				StatusCode: http.StatusBadRequest,
			}

			errMessage, _ := json.Marshal(err)

			c.JSON(http.StatusBadRequest, gin.H{string(errMessage): errMessage})
			return
		}

		defer c.Request.Body.Close()

		if err := c.Request.ParseForm(); err != nil {
			errJson, _ := json.Marshal(err)
			c.JSON(http.StatusBadRequest, gin.H{string(errJson): errJson})
			return
		}

		user_email := c.Request.FormValue("email")
		user_password := c.Request.FormValue("password")

		if strings.TrimSpace(user_email) == "" || strings.TrimSpace(user_password) == "" {
			errMessage := handleError.ErrorWithCode{
				Error:      "Email or Password Can't be Empty",
				StatusCode: http.StatusBadRequest,
			}

			jsonError, _ := json.Marshal(errMessage)

			c.JSON(http.StatusBadRequest, gin.H{string(jsonError): jsonError})
			return
		}

		c.Next()
	}
}

func ValidateUserMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Content-Type", "application/json")
		defer c.Request.Body.Close()

		tokenString := c.Request.Header.Get("Authorization")
		if strings.TrimSpace(tokenString) == "" || !strings.HasPrefix(tokenString, "Bearer ") {
			errResponse := handleError.ErrorWithCode{
				Error:      "Missing or invalid Authorization header",
				StatusCode: http.StatusBadRequest,
			}
			c.JSON(http.StatusBadRequest, gin.H{"error": errResponse})
			c.Abort()
			return
		}

		// Parse the JWT token
		token, err := jwt.Parse(tokenString[7:], func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(os.Getenv("JWT_SECRET_KEY")), nil
		})

		if err != nil {
			errResponse := handleError.ErrorWithCode{
				Error:      "JWT parsing failed or expired",
				StatusCode: http.StatusUnauthorized,
			}
			c.JSON(http.StatusUnauthorized, gin.H{"error": errResponse})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid JWT token"})
			c.Abort()
			return
		}

		// Check expiration
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "JWT expired"})
			c.Abort()
			return
		}

		// Validate ID from query param
		id := c.Query("id")
		if !primitive.IsValidObjectID(id) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
			c.Abort()
			return
		}

		// Compare ID with claim
		if id != claims["ID"] {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Token ID mismatch"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func UpdateUserMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		var user user_model.User

		defer c.Request.Body.Close()

		if err := json.NewDecoder(c.Request.Body).Decode(&user); err != nil {
			middlewareError, _ := json.Marshal(handleError.ErrorWithCode{
				Error:      "Data Not Found",
				StatusCode: http.StatusNoContent,
			})
			c.JSON(http.StatusNoContent, gin.H{"error": middlewareError})
			c.Abort()
			return
		}

		if user.Email != "" {
			_, err := mail.ParseAddress(user.Email)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"Error": err})
			}
			c.Abort()
			return
		}
		c.Next()
	}
}

func validatePassword(s string) (hasNum, hasUpper, hasSpecial bool) {
	for _, value := range s {
		switch {
		case unicode.IsNumber(value):
			hasNum = true
		case unicode.IsUpper(value):
			hasUpper = true

		case unicode.IsSymbol(value) || unicode.IsPunct(value):
			hasSpecial = true
		}

	}
	return hasNum, hasUpper, hasSpecial
}
