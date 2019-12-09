package user

import "go.mongodb.org/mongo-driver/bson/primitive"

// User represents someone who uses gopherchatter.
type User struct {
	ID           primitive.ObjectID `bson:"_id,omitempty"`
	Name         string             `bson:"name"`
	PasswordHash string             `bson:"password_hash"`
}

// NewUser contains information needed to create a new user.
type NewUser struct {
	Name            string
	Password        string
	PasswordConfirm string
}
