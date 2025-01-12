package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/minisource/auth/api/dto"
	"github.com/minisource/auth/config"
	"github.com/minisource/auth/services"
	helper "github.com/minisource/common_go/http/helpers"
)

type OAuthHandler struct {
	service *services.OAuthService
}

func NewOAuthHandler(cfg *config.Config) *OAuthHandler {
	service := services.NewOAuthService(cfg)
	return &OAuthHandler{service: service}
}

// Create OAuthClient godoc
// @Summary Create OAuthClient
// @Description Create OAuthClient
// @Tags OAuthClient
// @Accept  json
// @Produce  json
// @Success 200 {object} helper.BaseHttpResponse "Success"
// @Failure 400 {object} helper.BaseHttpResponse "Failed"
// @Router /v1/oauth/ [post]
func (h *OAuthHandler) Create(c *gin.Context) {
	req := new(dto.CreateOAuthClientRequest)
	err := c.ShouldBindJSON(&req)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest,
			helper.GenerateBaseResponseWithValidationError(nil, false, helper.ValidationError, err))
		return
	}
	client, err := h.service.CreateClient(req)
	if err != nil {
		c.AbortWithStatusJSON(helper.TranslateErrorToStatusCode(err),
			helper.GenerateBaseResponseWithError(nil, false, helper.InternalError, err))
		return
	}

	c.JSON(http.StatusCreated, helper.GenerateBaseResponse(client, true, helper.Success))
}

// GetAll OAuthClients godoc
// @Summary Create OAuthClients
// @Description Create OAuthClients
// @Tags OAuthClients
// @Accept  json
// @Produce  json
// @Success 200 {object} helper.BaseHttpResponse "Success"
// @Failure 400 {object} helper.BaseHttpResponse "Failed"
// @Router /v1/oauth/ [get]
func (h *OAuthHandler) GetAll(c *gin.Context) {
	clients, err := h.service.GetAllClients()
	if err != nil {
		c.AbortWithStatusJSON(helper.TranslateErrorToStatusCode(err),
			helper.GenerateBaseResponseWithError(nil, false, helper.InternalError, err))
		return
	}

	c.JSON(http.StatusOK, helper.GenerateBaseResponse(clients, true, helper.Success))
}

// Delete OAuthClient godoc
// @Summary Delete OAuthClient
// @Description Delete OAuthClient
// @Tags OAuthClient
// @Accept  json
// @Produce  json
// @Param id path string true "Id"
// @Success 200 {object} helper.BaseHttpResponse "Success"
// @Failure 400 {object} helper.BaseHttpResponse "Failed"
// @Router /v1/oauth/id [delete]
func (h *OAuthHandler) Delete(c *gin.Context) {
	id := c.Params.ByName("id")
	if id == "" {
		c.AbortWithStatusJSON(http.StatusNotFound,
			helper.GenerateBaseResponse(nil, false, helper.ValidationError))
		return
	}

	err := h.service.DeleteClient(id)
	if err != nil {
		c.AbortWithStatusJSON(helper.TranslateErrorToStatusCode(err),
			helper.GenerateBaseResponseWithError(nil, false, helper.InternalError, err))
		return
	}

	c.JSON(http.StatusOK, helper.GenerateBaseResponse(nil, true, 0))
}

// GetOAuthClient godoc
// @Summary Get a OAuthClient
// @Description Get a OAuthClient
// @Tags OAuthClient
// @Accept json
// @produces json
// @Param id path string true "Id"
// @Success 200 {object} helper.BaseHttpResponse{result=dto.GetOAuthClientResponse} "GetOAuthClient response"
// @Failure 400 {object} helper.BaseHttpResponse "Bad request"
// @Failure 404 {object} helper.BaseHttpResponse "Not found"
// @Router /v1/oauth/{id} [get]
func (h *OAuthHandler) GetById(c *gin.Context) {
	id := c.Params.ByName("id")
	if id == "" {
		c.AbortWithStatusJSON(http.StatusNotFound,
			helper.GenerateBaseResponse(nil, false, helper.ValidationError))
		return
	}

	client, err := h.service.GetClient(id)
	if err != nil {
		c.AbortWithStatusJSON(helper.TranslateErrorToStatusCode(err),
			helper.GenerateBaseResponseWithError(nil, false, helper.InternalError, err))
		return
	}

	c.JSON(http.StatusOK, helper.GenerateBaseResponse(client, true, 0))
}

// GenerateOAuthToken godoc
// @Summary Get a OAuthClientToken
// @Description Get a OAuthClientToken
// @Tags OAuthClientToken
// @Accept json
// @produces json
// @Failure 400 {object} helper.BaseHttpResponse "Bad request"
// @Failure 404 {object} helper.BaseHttpResponse "Not found"
// @Router /v1/oauth/GenerateToken [post]
func (h *OAuthHandler) GenerateToken(c *gin.Context) {
	req := new(dto.GenerateTokenRequest)
	err := c.ShouldBindJSON(&req)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest,
			helper.GenerateBaseResponseWithValidationError(nil, false, helper.ValidationError, err))
		return
	}
	token, err := h.service.GenerateToken(req)
	if err != nil {
		c.AbortWithStatusJSON(helper.TranslateErrorToStatusCode(err),
			helper.GenerateBaseResponseWithError(nil, false, helper.InternalError, err))
		return
	}

	c.JSON(http.StatusOK, helper.GenerateBaseResponse(token, true, 0))
}

// ValidateToken godoc
// @Summary ValidateToken
// @Description ValidateToken
// @Tags ValidateToken
// @Accept json
// @produces json
// @Failure 400 {object} helper.BaseHttpResponse "Bad request"
// @Failure 404 {object} helper.BaseHttpResponse "Not found"
// @Router /v1/oauth/ValidateToken [post]
func (h *OAuthHandler) ValidateToken(c *gin.Context) {
	req := new(dto.ValidateTokenRequest)
	err := c.ShouldBindJSON(&req)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest,
			helper.GenerateBaseResponseWithValidationError(nil, false, helper.ValidationError, err))
		return
	}
	introspection, err := h.service.ValidateToken(req.Token)
	if err != nil {
		c.AbortWithStatusJSON(helper.TranslateErrorToStatusCode(err),
			helper.GenerateBaseResponseWithError(nil, false, helper.InternalError, err))
		return
	}

	c.JSON(http.StatusOK, helper.GenerateBaseResponse(introspection, true, 0))
}
