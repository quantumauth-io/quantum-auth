package database

import (
	"github.com/Madeindreams/quantum-go-utils/database"
)

type Repo interface {
}

type QuantumAuthRepository struct {
	db database.QuantumAuthDatabase
}

func NewRepository(db database.QuantumAuthDatabase) *QuantumAuthRepository {
	return &QuantumAuthRepository{db}
}
