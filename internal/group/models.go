package group

import "go.mongodb.org/mongo-driver/bson/primitive"

// Chat represents a group chat.
type Chat struct {
	ID      primitive.ObjectID   `bson:"_id,omitempty"`
	Name    string               `bson:"name"`
	Admin   primitive.ObjectID   `bson:"admin"`
	Members []primitive.ObjectID `bson:"members"`
}
