package user_services

import (
	"context"
	"net/http"
	"time"

	connectDb "github.com/Sarvan18/Backend-Setup-Golang.git/golang-Backend-Setup/config"
	"github.com/Sarvan18/Backend-Setup-Golang.git/golang-Backend-Setup/helpers"
	user_model "github.com/Sarvan18/Backend-Setup-Golang.git/golang-Backend-Setup/models"
	handleError "github.com/Sarvan18/Backend-Setup-Golang.git/golang-Backend-Setup/utils"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

var users *mongo.Collection = connectDb.GetCollection(*connectDb.Client, "users")

func RegisterUser(user *user_model.User) (*mongo.InsertOneResult, *handleError.ErrorWithCode) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)

	defer cancel()

	count, err := users.CountDocuments(ctx, bson.M{"email": user.Email})

	if err != nil {
		return nil, &handleError.ErrorWithCode{
			Error:      err.Error(),
			StatusCode: http.StatusInternalServerError,
		}
	}

	if count > 0 {
		return nil, &handleError.ErrorWithCode{
			Error:      "User with Same Name Already Exists",
			StatusCode: http.StatusResetContent,
		}
	}

	var validator = validator.New()

	if err = validator.Struct(user); err != nil {
		return nil, &handleError.ErrorWithCode{
			Error:      err.Error(),
			StatusCode: http.StatusBadRequest,
		}
	}

	user.CreatedAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	user.UpdatedAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

	hashedPassword, err := helpers.HashPassword(user.Password)

	if err != nil {
		return nil, &handleError.ErrorWithCode{
			Error:      err.Error(),
			StatusCode: http.StatusInternalServerError,
		}
	}

	user.Password = hashedPassword
	user.ConfirmPassword = hashedPassword

	user.ID = primitive.NewObjectID()

	insertionResult, err := users.InsertOne(ctx, user)

	if err != nil {
		return nil, &handleError.ErrorWithCode{
			Error:      err.Error(),
			StatusCode: http.StatusInternalServerError,
		}
	}

	return insertionResult, nil
}

func LoginUser(email, password string) (*user_model.UserLoginToken, *handleError.ErrorWithCode) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)

	defer cancel()

	filter := bson.M{"email": email}

	var user user_model.User

	if err := users.FindOne(ctx, filter, nil).Decode(&user); err != nil {
		return nil, &handleError.ErrorWithCode{
			Error:      err.Error(),
			StatusCode: http.StatusNotFound,
		}
	}

	var err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))

	if err != nil {
		return nil, &handleError.ErrorWithCode{
			Error:      err.Error(),
			StatusCode: http.StatusUnauthorized,
		}
	}

	jwt, jwtErr := helpers.GenerateJWT(&user)

	if jwtErr != nil {
		return nil, jwtErr
	}

	jwtRes := &user_model.UserLoginToken{
		Accesstoken: jwt,
		ID:          user.ID,
	}

	return jwtRes, nil

}
