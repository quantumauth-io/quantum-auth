package database

import (
	"context"
	"encoding/json"
	"time"
)

type ProductType string

const (
	ProductTypeItem         ProductType = "item"
	ProductTypeService      ProductType = "service"
	ProductTypeSubscription ProductType = "subscription"
)

type BillingIntervalUnit string

const (
	BillingUnitDay   BillingIntervalUnit = "day"
	BillingUnitWeek  BillingIntervalUnit = "week"
	BillingUnitMonth BillingIntervalUnit = "month"
	BillingUnitYear  BillingIntervalUnit = "year"
)

type Product struct {
	ProductID string
	AppID     string

	Type        ProductType
	Name        string
	Description *string
	Slug        string

	PriceAmount   string // keep as string to avoid float issues; matches numeric
	PriceCurrency string

	// subscription config (only set when Type == subscription)
	BillingIntervalCount *int
	BillingIntervalUnit  *BillingIntervalUnit
	BillingAnchor        *string // currently "purchase_date"

	StockQuantity *int64
	SoldCount     int64

	IsActive bool
	Metadata json.RawMessage

	CreatedAt time.Time
	UpdatedAt time.Time
}

type CreateProductInput struct {
	AppID string

	Type        ProductType
	Name        string
	Description *string
	Slug        string

	PriceAmount   string // numeric as string: "10.000000"
	PriceCurrency string // default "USD" if empty

	// subscription-only
	BillingIntervalCount *int
	BillingIntervalUnit  *BillingIntervalUnit
	BillingAnchor        *string // default "purchase_date" for subscriptions

	// inventory (items)
	StockQuantity *int64

	Metadata json.RawMessage
}

type UpdateProductByIDInput struct {
	// editable fields
	Type        *ProductType
	Name        *string
	Description **string // pointer-to-pointer allows setting NULL vs no-change
	Slug        *string

	PriceAmount   *string
	PriceCurrency *string

	BillingIntervalCount *int
	BillingIntervalUnit  *BillingIntervalUnit
	BillingAnchor        **string // allow nulling

	StockQuantity **int64 // allow nulling

	IsActive *bool

	Metadata *json.RawMessage
}

// CreateProduct inserts a new product for an app.
func (r *QuantumAuthRepository) CreateProduct(ctx context.Context, in CreateProductInput) (*Product, error) {
	const q = `
		INSERT INTO products (
			app_id,
			type, name, description, slug,
			price_amount, price_currency,
			billing_interval_count, billing_interval_unit, billing_anchor,
			stock_quantity,
			metadata
		)
		VALUES (
			$1,
			$2, $3, $4, $5,
			$6, COALESCE(NULLIF($7, ''), 'USD'),
			$8, $9, $10,
			$11,
			COALESCE($12, '{}'::jsonb)
		)
		RETURNING
			product_id, app_id,
			type, name, description, slug,
			price_amount::text, price_currency,
			billing_interval_count, billing_interval_unit, billing_anchor,
			stock_quantity, sold_count,
			is_active, metadata,
			created_at, updated_at;
	`

	var meta any = nil
	if len(in.Metadata) > 0 {
		meta = in.Metadata
	}

	var p Product
	row, err := r.db.QueryRow(ctx, q,
		in.AppID,
		string(in.Type),
		in.Name,
		in.Description,
		in.Slug,
		in.PriceAmount,
		in.PriceCurrency,
		in.BillingIntervalCount,
		nullableString(in.BillingIntervalUnit),
		in.BillingAnchor,
		in.StockQuantity,
		meta,
	)
	if err != nil {
		return nil, err
	}

	var billingUnit *string
	if err := row.Scan(
		&p.ProductID, &p.AppID,
		&p.Type, &p.Name, &p.Description, &p.Slug,
		&p.PriceAmount, &p.PriceCurrency,
		&p.BillingIntervalCount, &billingUnit, &p.BillingAnchor,
		&p.StockQuantity, &p.SoldCount,
		&p.IsActive, &p.Metadata,
		&p.CreatedAt, &p.UpdatedAt,
	); err != nil {
		return nil, err
	}

	if billingUnit != nil {
		u := BillingIntervalUnit(*billingUnit)
		p.BillingIntervalUnit = &u
	}

	return &p, nil
}

// GetProductsByAppID lists products owned by an app.
func (r *QuantumAuthRepository) GetProductsByAppID(ctx context.Context, appID string) ([]*Product, error) {
	const q = `
		SELECT
			product_id, app_id,
			type, name, description, slug,
			price_amount::text, price_currency,
			billing_interval_count, billing_interval_unit, billing_anchor,
			stock_quantity, sold_count,
			is_active, metadata,
			created_at, updated_at
		FROM products
		WHERE app_id = $1
		ORDER BY created_at ASC;
	`

	rows, err := r.db.Query(ctx, q, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*Product
	for rows.Next() {
		var p Product
		var billingUnit *string

		if err := rows.Scan(
			&p.ProductID, &p.AppID,
			&p.Type, &p.Name, &p.Description, &p.Slug,
			&p.PriceAmount, &p.PriceCurrency,
			&p.BillingIntervalCount, &billingUnit, &p.BillingAnchor,
			&p.StockQuantity, &p.SoldCount,
			&p.IsActive, &p.Metadata,
			&p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			return nil, err
		}

		if billingUnit != nil {
			u := BillingIntervalUnit(*billingUnit)
			p.BillingIntervalUnit = &u
		}

		out = append(out, &p)
	}

	return out, rows.Err()
}

// GetProductByID returns one product by its product_id.
func (r *QuantumAuthRepository) GetProductByID(ctx context.Context, productID string) (*Product, error) {
	const q = `
		SELECT
			product_id, app_id,
			type, name, description, slug,
			price_amount::text, price_currency,
			billing_interval_count, billing_interval_unit, billing_anchor,
			stock_quantity, sold_count,
			is_active, metadata,
			created_at, updated_at
		FROM products
		WHERE product_id = $1;
	`

	var p Product
	var billingUnit *string

	row, err := r.db.QueryRow(ctx, q, productID)
	if err != nil {
		return nil, err
	}

	if err := row.Scan(
		&p.ProductID, &p.AppID,
		&p.Type, &p.Name, &p.Description, &p.Slug,
		&p.PriceAmount, &p.PriceCurrency,
		&p.BillingIntervalCount, &billingUnit, &p.BillingAnchor,
		&p.StockQuantity, &p.SoldCount,
		&p.IsActive, &p.Metadata,
		&p.CreatedAt, &p.UpdatedAt,
	); err != nil {
		return nil, err
	}

	if billingUnit != nil {
		u := BillingIntervalUnit(*billingUnit)
		p.BillingIntervalUnit = &u
	}

	return &p, nil
}

// UpdateProductByID updates fields on a product (partial update).
//
// Important: some fields use **T to distinguish "set NULL" vs "no change":
//   - Description **string
//   - StockQuantity **int64
//   - BillingAnchor **string
func (r *QuantumAuthRepository) UpdateProductByID(ctx context.Context, productID string, in UpdateProductByIDInput) (*Product, error) {
	const q = `
		UPDATE products
		SET
			type = COALESCE($2, type),
			name = COALESCE($3, name),
			description = COALESCE($4, description),
			slug = COALESCE($5, slug),

			price_amount = COALESCE($6, price_amount),
			price_currency = COALESCE(NULLIF($7, ''), price_currency),

			billing_interval_count = COALESCE($8, billing_interval_count),
			billing_interval_unit = COALESCE($9, billing_interval_unit),
			billing_anchor = COALESCE($10, billing_anchor),

			stock_quantity = COALESCE($11, stock_quantity),

			is_active = COALESCE($12, is_active),
			metadata = COALESCE($13, metadata),

			updated_at = now()
		WHERE product_id = $1
		RETURNING
			product_id, app_id,
			type, name, description, slug,
			price_amount::text, price_currency,
			billing_interval_count, billing_interval_unit, billing_anchor,
			stock_quantity, sold_count,
			is_active, metadata,
			created_at, updated_at;
	`

	// These "any" values become NULL when we want "no change" OR when
	// the caller explicitly wants to set NULL depending on pointer depth.
	var (
		ptype  any = nil
		desc   any = nil
		anchor any = nil
		stock  any = nil
		meta   any = nil
		unit   any = nil
	)

	if in.Type != nil {
		ptype = string(*in.Type)
	}
	if in.Description != nil {
		// in.Description != nil means caller wants to set description (maybe NULL)
		if *in.Description == nil {
			desc = nil
		} else {
			desc = **in.Description
		}
	}
	if in.BillingAnchor != nil {
		if *in.BillingAnchor == nil {
			anchor = nil
		} else {
			anchor = **in.BillingAnchor
		}
	}
	if in.StockQuantity != nil {
		if *in.StockQuantity == nil {
			stock = nil
		} else {
			stock = **in.StockQuantity
		}
	}
	if in.Metadata != nil {
		meta = *in.Metadata
	}
	if in.BillingIntervalUnit != nil {
		unit = string(*in.BillingIntervalUnit)
	}

	var p Product
	var billingUnit *string

	row, err := r.db.QueryRow(ctx, q,
		productID,
		ptype,
		in.Name,
		desc,
		in.Slug,
		in.PriceAmount,
		in.PriceCurrency,
		in.BillingIntervalCount,
		unit,
		anchor,
		stock,
		in.IsActive,
		meta,
	)
	if err != nil {
		return nil, err
	}

	if err := row.Scan(
		&p.ProductID, &p.AppID,
		&p.Type, &p.Name, &p.Description, &p.Slug,
		&p.PriceAmount, &p.PriceCurrency,
		&p.BillingIntervalCount, &billingUnit, &p.BillingAnchor,
		&p.StockQuantity, &p.SoldCount,
		&p.IsActive, &p.Metadata,
		&p.CreatedAt, &p.UpdatedAt,
	); err != nil {
		return nil, err
	}

	if billingUnit != nil {
		u := BillingIntervalUnit(*billingUnit)
		p.BillingIntervalUnit = &u
	}

	return &p, nil
}

// DeleteProductByID deletes a product (hard delete). Consider soft delete via is_active in v1.
func (r *QuantumAuthRepository) DeleteProductByID(ctx context.Context, productID string) error {
	const q = `DELETE FROM products WHERE product_id = $1;`
	_, err := r.db.Exec(ctx, q, productID)
	return err
}

// ----------------------------
// Helpers
// ----------------------------

func nullableString[T ~string](p *T) any {
	if p == nil {
		return nil
	}
	s := string(*p)
	return s
}
