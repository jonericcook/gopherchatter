package user

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// User represents someone who uses gopherchatter.
type User struct {
	ID           primitive.ObjectID `bson:"_id,omitempty"`
	Username     string             `bson:"username"`
	PasswordHash string             `bson:"password_hash"`
}

// Credentials contains information needed to authenticate a user.
type Credentials struct {
	Username string
	Password string
}
