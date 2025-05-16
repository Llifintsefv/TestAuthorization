package middleware

import (
	"TestTaskAuthorization/internal/auth"
	"log/slog"
	"strings"

	"github.com/gofiber/fiber/v2"
)

type AuthMiddleware struct {
	TokenParser auth.Auth
	Logger      *slog.Logger
}

func NewAuthMiddleware(tokenParser auth.Auth, logger *slog.Logger) *AuthMiddleware {
	return &AuthMiddleware{
		TokenParser: tokenParser,
		Logger:      logger,
	}
}

const (
	UserCtxKey   = "userGUID"
	authHeader   = "Authorization"
	bearerPrefix = "Bearer "
)

func (am *AuthMiddleware) AuthMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		header := c.Get(authHeader)
		if header == "" {
			am.Logger.Error("authorization header is not provided")
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"reason": "Заголовок Authorization отсутствует",
			})
		}

		if !strings.HasPrefix(header, bearerPrefix) {
			am.Logger.Error("invalid authorization header")
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"reason": "Неверный заголовок Authorization",
			})
		}

		tokenString := strings.TrimPrefix(header, bearerPrefix)
		if tokenString == "" {
			am.Logger.Error("invalid authorization header")
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"reason": "Неверный заголовок Authorization",
			})
		}

		claims, err := am.TokenParser.ParseAccessToken(tokenString)
		if err != nil {
			am.Logger.Error("failed to parse access token", "error", err)
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"reason": "Неверный заголовок Authorization",
			})
		}

		c.Locals(UserCtxKey, claims.UserGUID)
		return c.Next()
	}
}
