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

// DeleteChatMessages deletes a chat messages.
func DeleteChatMessages(ctx context.Context, db *mongo.Database, chatID primitive.ObjectID) error {
	filter := bson.M{"chat_id": chatID}
	_, err := db.Collection(messageCollection).DeleteMany(ctx, filter)
	if err != nil {
		return status.Errorf(
			codes.Internal, "deleteing messages",
		)
	}
	return nil
}

// GetChatMessages returns all the messages for a chat.
func GetChatMessages(ctx context.Context, db *mongo.Database, chatID primitive.ObjectID) ([]Message, error) {
	filter := bson.M{"chat_id": chatID}
	cursor, err := db.Collection(messageCollection).Find(ctx, filter)
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "getting messages",
		)
	}
	var messages []Message
	if err = cursor.All(ctx, &messages); err != nil {
		return nil, status.Errorf(
			codes.InvalidArgument, "getting messages from cursor",
		)
	}
	return messages, nil
}
