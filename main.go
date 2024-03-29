package main

import (
	"github.com/Rahul06x1/go_jwt/controllers"
	"github.com/Rahul06x1/go_jwt/initializers"
	"github.com/Rahul06x1/go_jwt/middleware"
	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDB()
	initializers.SyncDatabase()
}

func main() {
	r := gin.Default()

	r.POST("/signup", controllers.SignUp)
	r.POST("/login", controllers.Login)
	r.GET("/validate", middleware.RequireAuth, controllers.Validate)
	
	r.Run()
}
