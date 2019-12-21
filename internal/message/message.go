package message

import (
	"context"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const messageCollection = "messages"

// Create inserts a new message into the database.
func Create(ctx context.Context, db *mongo.Database, m Message) (*Message, error) {
	result, err := db.Collection(messageCollection).InsertOne(ctx, m)
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "creating message",
		)
	}
	m.ID = result.InsertedID.(primitive.ObjectID)
	return &m, nil
}

// Get checks if a message exists.
func Get(ctx context.Context, db *mongo.Database, chatID primitive.ObjectID) (*Message, error) {
	var message Message
	filter := bson.M{"_id": chatID}
	if err := db.Collection(messageCollection).FindOne(ctx, filter).Decode(&message); err != nil {
		return nil, status.Errorf(
			codes.NotFound, "message id does not exist",
		)
	}
	return &message, nil
}
