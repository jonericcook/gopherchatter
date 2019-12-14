package individual

import "go.mongodb.org/mongo-driver/bson/primitive"

// Chat represents a individual chat.
type Chat struct {
	ID      primitive.ObjectID   `bson:"_id,omitempty"`
	Members []primitive.ObjectID `bson:"members"`
}
