package group

import (
	"context"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const groupChatCollection = "groupchats"

// CreateChat inserts a new group chat into the database.
func CreateChat(ctx context.Context, db *mongo.Database, nc NewChat) (*Chat, error) {
	admin, err := primitive.ObjectIDFromHex(nc.Admin)
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	member, err := primitive.ObjectIDFromHex(nc.Members[0])
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	result, err := db.Collection(groupChatCollection).InsertOne(ctx, bson.D{
		{Key: "name", Value: nc.Name},
		{Key: "admin", Value: admin},
		{Key: "members", Value: bson.A{member}},
	})
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	c := Chat{
		ID:      result.InsertedID.(primitive.ObjectID).Hex(),
		Name:    nc.Name,
		Admin:   nc.Admin,
		Members: nc.Members,
	}
	return &c, nil
}
