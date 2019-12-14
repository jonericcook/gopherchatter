package individual

import (
	"context"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const individualChatCollection = "individualchats"

// ChatUsersExists checks if an individual chat exists.
func ChatUsersExists(ctx context.Context, db *mongo.Database, c Chat) bool {
	var chat Chat
	filter := bson.M{"members": bson.M{"$all": bson.A{c.Members[0], c.Members[0]}}}
	if err := db.Collection(individualChatCollection).FindOne(ctx, filter).Decode(&chat); err != nil {
		return false
	}
	return true
}

// CreateChat inserts a new group chat into the database.
func CreateChat(ctx context.Context, db *mongo.Database, c Chat) (*Chat, error) {
	result, err := db.Collection(individualChatCollection).InsertOne(ctx, c)
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "creating group chat",
		)
	}
	c.ID = result.InsertedID.(primitive.ObjectID)
	return &c, nil
}
