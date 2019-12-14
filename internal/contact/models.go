package contact

import "go.mongodb.org/mongo-driver/bson/primitive"

// Contact represents a user who is a contact.
type Contact struct {
	ID    primitive.ObjectID `bson:"_id,omitempty"`
	Owner primitive.ObjectID `bson:"owner"`
	User  primitive.ObjectID `bson:"user"`
}
