package handler

import (
	"TestTaskAuthorization/internal/models"
	"TestTaskAuthorization/internal/service"
	"log/slog"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

type handler struct {
	service service.Service
	logger  *slog.Logger
}

type Handler interface {
	GetTokenPair(c *fiber.Ctx) error
	RefreshToken(c *fiber.Ctx) error
	GetUserGUID(c *fiber.Ctx) error
	UserLogout(c *fiber.Ctx) error
}

func NewHandler(service service.Service, logger *slog.Logger) Handler {
	return &handler{service: service, logger: logger}
}

func (h *handler) GetTokenPair(c *fiber.Ctx) error {
	ctx := c.Context()
	var req models.GetTokenRequest
	if err := c.BodyParser(&req); err != nil {
		h.logger.ErrorContext(ctx, "error parsing request body", slog.Any("error", err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error parsing request body"})
	}

	if _, err := uuid.Parse(req.UserGUID); err != nil {
		h.logger.ErrorContext(ctx, "Invalid userID", slog.Any("error", err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid userID"})
	}

	clientIP := c.IP()
	userAgent := string(c.Request().Header.UserAgent())

	tokenPair, err := h.service.GetTokenPair(ctx, req.UserGUID, clientIP, userAgent)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to get token", slog.Any("error", err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to generate token pair"})
	}
	return c.Status(http.StatusOK).JSON(tokenPair)

}

func (h *handler) RefreshToken(c *fiber.Ctx) error {
	ctx := c.Context()
	var req models.RefreshTokenRequest
	if err := c.BodyParser(&req); err != nil {
		h.logger.ErrorContext(ctx, "error parsing request body", slog.Any("error", err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error parsing request body"})
	}

	clientIP := c.IP()
	userAgent := string(c.Request().Header.UserAgent())

	newTokenPair, err := h.service.RefreshToken(ctx, req.RefreshToken, clientIP, userAgent)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to refresh token", slog.Any("error", err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to refresh token"})
	}
	return c.Status(http.StatusOK).JSON(newTokenPair)

}

func (h *handler) GetUserGUID(c *fiber.Ctx) error {
	userGUID := c.Locals("userGUID")
	return c.Status(http.StatusOK).JSON(fiber.Map{"userGUID": userGUID})
}

func (h *handler) UserLogout(c *fiber.Ctx) error {
	ctx := c.Context()
	userGUID := c.Locals("userGUID").(string)
	err := h.service.UserLogout(ctx, userGUID)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to logout user", slog.Any("error", err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to logout user"})
	}
	return c.Status(http.StatusOK).JSON(fiber.Map{"message": "User logged out successfully"})
}
