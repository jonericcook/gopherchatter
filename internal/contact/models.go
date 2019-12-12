package contact

import "go.mongodb.org/mongo-driver/bson/primitive"

// Contact represents a user who is a contact.
type Contact struct {
	ID      primitive.ObjectID `bson:"_id,omitempty"`
	OwnerID primitive.ObjectID `bson:"owner_id"`
	UserID  primitive.ObjectID `bson:"user_id"`
}
