package initializers

import "github.com/Rahul06x1/go_jwt/models"

func SyncDatabase() {
	DB.AutoMigrate(&models.User{})
}