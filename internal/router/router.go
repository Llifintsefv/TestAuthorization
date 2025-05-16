package router

import (
	"TestTaskAuthorization/internal/handler"
	"TestTaskAuthorization/internal/middleware"

	"github.com/gofiber/fiber/v2"
)

func SetupRouter(handler handler.Handler, middleware *middleware.AuthMiddleware) *fiber.App {
	app := fiber.New()

	app.Post("/auth/token", handler.GetTokenPair)
	app.Post("/auth/refresh", handler.RefreshToken)

	protectedApiV1 := app.Group("/")
	protectedApiV1.Use(middleware.AuthMiddleware())
	protectedApiV1.Get("users/me",handler.GetUserGUID)
	return app
}
