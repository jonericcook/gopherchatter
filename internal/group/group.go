package group

import (
	"context"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const groupChatCollection = "groupchats"

// CreateChat inserts a new group chat into the database.
func CreateChat(ctx context.Context, db *mongo.Database, c Chat) (*Chat, error) {
	result, err := db.Collection(groupChatCollection).InsertOne(ctx, c)
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "creating group chat",
		)
	}
	c.ID = result.InsertedID.(primitive.ObjectID)
	return &c, nil
}
