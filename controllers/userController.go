package user_controllers

import (
	"encoding/json"
	"net/http"

	user_middlewares "github.com/Sarvan18/Backend-Setup-Golang.git/golang-Backend-Setup/middlewares"
	user_model "github.com/Sarvan18/Backend-Setup-Golang.git/golang-Backend-Setup/models"
	user_services "github.com/Sarvan18/Backend-Setup-Golang.git/golang-Backend-Setup/services"
	"github.com/gin-gonic/gin"
)

func RegisterUserHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		res, err := user_services.RegisterUser(user_middlewares.User)

		defer c.Request.Body.Close()

		if err != nil {
			c.JSON(int(err.StatusCode), gin.H{"Error": err.Error})
			return
		}

		c.JSON(http.StatusOK, res)
	}
}

func LoginUserHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		user_email := c.Request.FormValue("email")
		user_password := c.Request.FormValue("password")

		defer c.Request.Body.Close()

		jwt, err := user_services.LoginUser(user_email, user_password)

		if err != nil {
			c.JSON(int(err.StatusCode), err.Error)
			return
		}

		c.JSON(http.StatusOK, jwt)
	}
}

func GetUserHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		userId := c.Query("id")
		user, err := user_services.GetUserById(userId)

		defer c.Request.Body.Close()

		if err != nil {
			c.JSON(int(err.StatusCode), err.Error)
			return

		}

		c.JSON(http.StatusOK, user)

	}
}

func UpdateUserHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		var user user_model.User

		defer c.Request.Body.Close()

		if err := json.NewDecoder(c.Request.Body).Decode(&user); err != nil {
			c.JSON(http.StatusNoContent, gin.H{"Error": "No data Found"})
			return
		}

		id := c.Query("id")

		res, err := user_services.UpdateUser(&user, id)

		if err != nil {
			c.JSON(int(err.StatusCode), err.Error)
			return
		}

		c.JSON(http.StatusOK, res)
	}
}

func DeleteUserHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Query("id")

		res, err := user_services.DeleteUser(id)

		if err != nil {
			c.JSON(int(err.StatusCode), err.Error)
		}

		c.JSON(http.StatusOK, res)
	}
}
