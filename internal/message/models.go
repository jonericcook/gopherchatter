package message

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Message represents a message sent by a user.
type Message struct {
	ID       primitive.ObjectID `bson:"_id,omitempty"`
	ChatID   primitive.ObjectID `bson:"chat_id"`
	AuthorID primitive.ObjectID `bson:"author_id"`
	Contents string             `bson:"contents"`
	Created  int64              `bson:"created"`
}
