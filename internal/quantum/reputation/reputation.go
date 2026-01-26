package reputation

import (
	"math"
	"time"

	"github.com/shopspring/decimal"
)

// UserReputation is the minimal input needed to compute rating weight.
// Populate this from your user_reputation table (or default zeros if missing).
type UserReputation struct {
	PurchasesCount     int64
	DisputesFiledCount int64
	DisputesLostCount  int64
}

// WeightConfig controls the weighting policy.
// Keep these defaults stable; tweak by config when you iterate.
type WeightConfig struct {
	MinWeight decimal.Decimal // e.g. 0.05
	MaxWeight decimal.Decimal // e.g. 2.0

	// Verified ratings get full weight; unverified ratings are heavily discounted.
	VerifiedFactor   decimal.Decimal // e.g. 1.0
	UnverifiedFactor decimal.Decimal // e.g. 0.2

	// Account age ramp: age_days / AgeRampDays, clamped to [AgeMinFactor, 1.0]
	AgeRampDays  float64         // e.g. 90
	AgeMinFactor decimal.Decimal // e.g. 0.2

	// Purchase history factor: ln(1+purchases) / ln(1+PurchaseSaturation), clamped to [PurchaseMinFactor, 1.0]
	PurchaseSaturation float64         // e.g. 10
	PurchaseMinFactor  decimal.Decimal // e.g. 0.3

	// Dispute penalty:
	// loss_rate = (lost + 1) / (filed + 2)
	// dispute_factor = 1 - DisputePenaltySlope * loss_rate, clamped to [DisputeMinFactor, 1.0]
	DisputePenaltySlope float64         // e.g. 0.8
	DisputeMinFactor    decimal.Decimal // e.g. 0.2
}

func DefaultWeightConfig() WeightConfig {
	return WeightConfig{
		MinWeight: decimal.RequireFromString("0.05"),
		MaxWeight: decimal.RequireFromString("2.0"),

		VerifiedFactor:   decimal.RequireFromString("1.0"),
		UnverifiedFactor: decimal.RequireFromString("0.2"),

		AgeRampDays:  90,
		AgeMinFactor: decimal.RequireFromString("0.2"),

		PurchaseSaturation: 10,
		PurchaseMinFactor:  decimal.RequireFromString("0.3"),

		DisputePenaltySlope: 0.8,
		DisputeMinFactor:    decimal.RequireFromString("0.2"),
	}
}

// ComputeRatingWeight calculates the weight to store in app_ratings.weight.
//
// Inputs:
// - userCreatedAt: from users.created_at
// - rep: from user_reputation (if missing, treat as zeros)
// - verified: true if rating is linked to a verified purchase (order)
// - now: current time (injectable for tests)
// - cfg: weighting policy (use DefaultWeightConfig() initially)
//
// Output is clamped to [cfg.MinWeight, cfg.MaxWeight].
func ComputeRatingWeight(userCreatedAt time.Time, rep UserReputation, verified bool, now time.Time, cfg WeightConfig) decimal.Decimal {
	// 1) verified factor
	vf := cfg.UnverifiedFactor
	if verified {
		vf = cfg.VerifiedFactor
	}

	// 2) age factor
	ageDays := now.Sub(userCreatedAt).Hours() / 24.0
	if ageDays < 0 {
		ageDays = 0
	}
	ageFactorFloat := ageDays / cfg.AgeRampDays
	ageFactor := clampDecimal(decimal.NewFromFloat(ageFactorFloat), cfg.AgeMinFactor, decimal.NewFromInt(1))

	// 3) purchase factor (log curve)
	p := float64(rep.PurchasesCount)
	if p < 0 {
		p = 0
	}
	den := math.Log(1.0 + cfg.PurchaseSaturation)
	num := math.Log(1.0 + p)
	pfFloat := 0.0
	if den > 0 {
		pfFloat = num / den
	}
	purchaseFactor := clampDecimal(decimal.NewFromFloat(pfFloat), cfg.PurchaseMinFactor, decimal.NewFromInt(1))

	// 4) dispute factor
	// If never filed disputes => no penalty.
	disputeFactor := decimal.NewFromInt(1)
	if rep.DisputesFiledCount > 0 {
		filed := float64(rep.DisputesFiledCount)
		lost := float64(rep.DisputesLostCount)
		if filed < 0 {
			filed = 0
		}
		if lost < 0 {
			lost = 0
		}
		lossRate := (lost + 1.0) / (filed + 2.0) // smoothing
		dfFloat := 1.0 - cfg.DisputePenaltySlope*lossRate
		disputeFactor = clampDecimal(decimal.NewFromFloat(dfFloat), cfg.DisputeMinFactor, decimal.NewFromInt(1))
	}

	// Combine
	w := decimal.NewFromInt(1).
		Mul(vf).
		Mul(ageFactor).
		Mul(purchaseFactor).
		Mul(disputeFactor)

	return clampDecimal(w, cfg.MinWeight, cfg.MaxWeight)
}

func clampDecimal(x, min, max decimal.Decimal) decimal.Decimal {
	if x.LessThan(min) {
		return min
	}
	if x.GreaterThan(max) {
		return max
	}
	return x
}
