package message

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Message represents a message sent by a user.
type Message struct {
	ID       primitive.ObjectID `bson:"_id,omitempty"`
	ChatID   primitive.ObjectID `bson:"chat_id"`
	AuthorID primitive.ObjectID `bson:"author_id"`
	Contents string             `bson:"contents"`
	Created  time.Time          `bson:"created"`
}
