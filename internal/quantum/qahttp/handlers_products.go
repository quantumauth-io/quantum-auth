package qahttp

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	qagin "github.com/quantumauth-io/go-quantumauth-mw/gin"
	"github.com/quantumauth-io/quantum-auth/internal/quantum/database"
)

// CreateProduct
// @BasePath     /quantum-auth/v1/secured
// @Summary      Create product
// @Description  Create a product for an app (must be owned by the authenticated user).
// @Tags         developer products
// @Accept       json
// @Produce      json
// @Param        app_id  path      string               true  "App ID"
// @Param        body    body      createProductRequest true  "Create product payload"
// @Success      201     {object}  productResponse
// @Failure      400     {string}  string  "bad request"
// @Failure      401     {string}  string  "unauthorized"
// @Failure      403     {string}  string  "forbidden"
// @Failure      404     {string}  string  "not found"
// @Failure      500     {string}  string  "internal server error"
// @Router       /qa/apps/{app_id}/products [post]
func (sh *SecureHandlers) CreateProduct(c *gin.Context) {
	userID, ok := qagin.UserID(c)
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	appID := strings.TrimSpace(c.Param("app_id"))
	if appID == "" {
		c.JSON(http.StatusNotFound, "not found")
		return
	}

	// Ensure app exists + owned by caller
	app, err := sh.repo.GetAppByID(c.Request.Context(), appID)
	if err != nil {
		c.JSON(http.StatusNotFound, "not found")
		return
	}
	if app.OwnerUserID != userID {
		c.JSON(http.StatusForbidden, "forbidden")
		return
	}

	var req createProductRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, "bad request")
		return
	}

	// Basic server-side sanity: subscription fields required if subscription
	if req.Type == database.ProductTypeSubscription {
		if req.BillingIntervalCount == nil || req.BillingIntervalUnit == nil {
			c.JSON(http.StatusBadRequest, "bad request")
			return
		}
	}

	in := database.CreateProductInput{
		AppID: appID,

		Type:        req.Type,
		Name:        strings.TrimSpace(req.Name),
		Description: req.Description,
		Slug:        strings.TrimSpace(req.Slug),

		PriceAmount:   strings.TrimSpace(req.PriceAmount),
		PriceCurrency: strings.TrimSpace(req.PriceCurrency),

		BillingIntervalCount: req.BillingIntervalCount,
		BillingIntervalUnit:  req.BillingIntervalUnit,
		BillingAnchor:        req.BillingAnchor,

		StockQuantity: req.StockQuantity,

		Metadata: req.Metadata,
	}

	p, err := sh.repo.CreateProduct(c.Request.Context(), in)
	if err != nil {
		// TODO: translate unique constraint errors (slug) -> 409 if you want
		c.JSON(http.StatusInternalServerError, "internal server error")
		return
	}

	c.JSON(http.StatusCreated, toProductResponse(p))
}

// ListMyProducts
// @BasePath     /quantum-auth/v1/secured
// @Summary      List my products
// @Description  List products for an app (must be owned by the authenticated user).
// @Tags         developer products
// @Produce      json
// @Param        app_id  path      string  true  "App ID"
// @Success      200     {array}   productResponse
// @Failure      401     {string}  string  "unauthorized"
// @Failure      403     {string}  string  "forbidden"
// @Failure      404     {string}  string  "not found"
// @Failure      500     {string}  string  "internal server error"
// @Router       /qa/apps/{app_id}/products [get]
func (sh *SecureHandlers) ListMyProducts(c *gin.Context) {
	userID, ok := qagin.UserID(c)
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	appID := strings.TrimSpace(c.Param("app_id"))
	if appID == "" {
		c.JSON(http.StatusNotFound, "not found")
		return
	}

	app, err := sh.repo.GetAppByID(c.Request.Context(), appID)
	if err != nil {
		c.JSON(http.StatusNotFound, "not found")
		return
	}
	if app.OwnerUserID != userID {
		c.JSON(http.StatusForbidden, "forbidden")
		return
	}

	items, err := sh.repo.GetProductsByAppID(c.Request.Context(), appID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, "internal server error")
		return
	}

	out := make([]productResponse, 0, len(items))
	for _, p := range items {
		out = append(out, toProductResponse(p))
	}

	c.JSON(http.StatusOK, out)
}

// GetMyProduct
// @BasePath     /quantum-auth/v1/secured
// @Summary      Get my product
// @Description  Get a product by id (must be owned by the authenticated user via app ownership).
// @Tags         developer products
// @Produce      json
// @Param        product_id  path      string  true  "Product ID"
// @Success      200         {object}  productResponse
// @Failure      401         {string}  string  "unauthorized"
// @Failure      403         {string}  string  "forbidden"
// @Failure      404         {string}  string  "not found"
// @Failure      500         {string}  string  "internal server error"
// @Router       /qa/products/{product_id} [get]
func (sh *SecureHandlers) GetMyProduct(c *gin.Context) {
	userID, ok := qagin.UserID(c)
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	productID := strings.TrimSpace(c.Param("product_id"))
	if productID == "" {
		c.JSON(http.StatusNotFound, "not found")
		return
	}

	p, err := sh.repo.GetProductByID(c.Request.Context(), productID)
	if err != nil {
		c.JSON(http.StatusNotFound, "not found")
		return
	}

	app, err := sh.repo.GetAppByID(c.Request.Context(), p.AppID)
	if err != nil {
		c.JSON(http.StatusNotFound, "not found")
		return
	}
	if app.OwnerUserID != userID {
		c.JSON(http.StatusForbidden, "forbidden")
		return
	}

	c.JSON(http.StatusOK, toProductResponse(p))
}

// UpdateMyProduct
// @BasePath     /quantum-auth/v1/secured
// @Summary      Update my product
// @Description  Patch a product by id (must be owned by the authenticated user via app ownership).
// @Tags         developer products
// @Accept       json
// @Produce      json
// @Param        product_id  path      string               true  "Product ID"
// @Param        body        body      updateProductRequest true  "Patch product payload"
// @Success      200         {object}  productResponse
// @Failure      400         {string}  string  "bad request"
// @Failure      401         {string}  string  "unauthorized"
// @Failure      403         {string}  string  "forbidden"
// @Failure      404         {string}  string  "not found"
// @Failure      500         {string}  string  "internal server error"
// @Router       /qa/products/{product_id} [patch]
func (sh *SecureHandlers) UpdateMyProduct(c *gin.Context) {
	userID, ok := qagin.UserID(c)
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	productID := strings.TrimSpace(c.Param("product_id"))
	if productID == "" {
		c.JSON(http.StatusNotFound, "not found")
		return
	}

	// load product (and thus appId)
	p, err := sh.repo.GetProductByID(c.Request.Context(), productID)
	if err != nil {
		c.JSON(http.StatusNotFound, "not found")
		return
	}

	// ownership check
	app, err := sh.repo.GetAppByID(c.Request.Context(), p.AppID)
	if err != nil {
		c.JSON(http.StatusNotFound, "not found")
		return
	}
	if app.OwnerUserID != userID {
		c.JSON(http.StatusForbidden, "forbidden")
		return
	}

	var req updateProductRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, "bad request")
		return
	}

	in := database.UpdateProductByIDInput{
		Type:          req.Type,
		Name:          req.Name,
		Slug:          req.Slug,
		PriceAmount:   req.PriceAmount,
		PriceCurrency: req.PriceCurrency,

		BillingIntervalCount: req.BillingIntervalCount,
		BillingIntervalUnit:  req.BillingIntervalUnit,

		IsActive: req.IsActive,
	}

	// Description: if present, set it (could be empty string). If you need explicit nulling later,
	// we can switch to a custom nullable type.
	if req.Description != nil {
		tmp := req.Description
		in.Description = &tmp
	}

	// BillingAnchor: same
	if req.BillingAnchor != nil {
		tmp := req.BillingAnchor
		in.BillingAnchor = &tmp
	}

	// StockQuantity: same
	if req.StockQuantity != nil {
		tmp := req.StockQuantity
		in.StockQuantity = &tmp
	}

	if req.Metadata != nil {
		in.Metadata = req.Metadata
	}

	updated, err := sh.repo.UpdateProductByID(c.Request.Context(), productID, in)
	if err != nil {
		c.JSON(http.StatusInternalServerError, "internal server error")
		return
	}

	c.JSON(http.StatusOK, toProductResponse(updated))
}

// DeleteMyProduct
// @BasePath     /quantum-auth/v1/secured
// @Summary      Delete my product
// @Description  Delete a product by id (must be owned by the authenticated user via app ownership).
// @Tags         developer products
// @Produce      json
// @Param        product_id  path      string  true  "Product ID"
// @Success      204         {string}  string  "no content"
// @Failure      401         {string}  string  "unauthorized"
// @Failure      403         {string}  string  "forbidden"
// @Failure      404         {string}  string  "not found"
// @Failure      500         {string}  string  "internal server error"
// @Router       /qa/products/{product_id} [delete]
func (sh *SecureHandlers) DeleteMyProduct(c *gin.Context) {
	userID, ok := qagin.UserID(c)
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	productID := strings.TrimSpace(c.Param("product_id"))
	if productID == "" {
		c.JSON(http.StatusNotFound, "not found")
		return
	}

	p, err := sh.repo.GetProductByID(c.Request.Context(), productID)
	if err != nil {
		c.JSON(http.StatusNotFound, "not found")
		return
	}

	app, err := sh.repo.GetAppByID(c.Request.Context(), p.AppID)
	if err != nil {
		c.JSON(http.StatusNotFound, "not found")
		return
	}
	if app.OwnerUserID != userID {
		c.JSON(http.StatusForbidden, "forbidden")
		return
	}

	if err := sh.repo.DeleteProductByID(c.Request.Context(), productID); err != nil {
		c.JSON(http.StatusInternalServerError, "internal server error")
		return
	}

	c.Status(http.StatusNoContent)
}
