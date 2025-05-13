package helpers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	user_model "github.com/Sarvan18/Backend-Setup-Golang.git/golang-Backend-Setup/models"
	handleError "github.com/Sarvan18/Backend-Setup-Golang.git/golang-Backend-Setup/utils"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	res, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	if err != nil {
		return "", fmt.Errorf("error occured while hashing the password %w", err)
	}

	return string(res), nil
}

func GenerateJWT(user *user_model.User) (string, *handleError.ErrorWithCode) {
	userStruct := user_model.JwtSigning{
		ID: user.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    user.ID.Hex(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 30)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, userStruct)
	jwt, err := token.SignedString([]byte(os.Getenv("JWT_SECRET_KEY")))

	if err != nil {
		return "", &handleError.ErrorWithCode{Error: err.Error(), StatusCode: http.StatusInternalServerError}
	}

	return jwt, nil
}

func Marshal(data interface{}) ([]byte, error) {
	marshallData, err := json.Marshal(data)

	if err != nil {
		return nil, err
	}

	return marshallData, nil
}
