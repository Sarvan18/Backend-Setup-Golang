package user_routes

import (
	user_controllers "github.com/Sarvan18/Backend-Setup-Golang.git/golang-Backend-Setup/controllers"
	user_middlewares "github.com/Sarvan18/Backend-Setup-Golang.git/golang-Backend-Setup/middlewares"
	"github.com/gin-gonic/gin"
)

func UserRoutes(router *gin.Engine) {
	api := router.Group("/api")
	{
		user := api.Group("/user")
		user.POST("/", user_middlewares.UserLoginMiddleware(), user_controllers.GetUserHandler())
		user.POST("/register",
			user_middlewares.RegisterUserMiddleware(),
			user_controllers.RegisterUserHandler(),
		)
		user.POST("/login", user_middlewares.UserLoginMiddleware(), user_controllers.LoginUserHandler())
		user.PATCH("/update", user_middlewares.UserLoginMiddleware(), user_controllers.UpdateUserHandler())
		user.POST("/delete", user_middlewares.UserLoginMiddleware(), user_controllers.DeleteUserHandler())
	}
}
