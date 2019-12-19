package chat

import (
	"context"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const chatCollection = "chats"

// GetGroup checks if a user exists.
func GetGroup(ctx context.Context, db *mongo.Database, chatID primitive.ObjectID) (*Group, error) {
	var chat Group
	filter := bson.M{"_id": chatID}
	if err := db.Collection(chatCollection).FindOne(ctx, filter).Decode(&chat); err != nil {
		return nil, status.Errorf(
			codes.NotFound, "chat id does not exist",
		)
	}
	return &chat, nil
}

// GetIndividual checks if a user exists.
func GetIndividual(ctx context.Context, db *mongo.Database, chatID primitive.ObjectID) (*Individual, error) {
	var chat Individual
	filter := bson.M{"_id": chatID}
	if err := db.Collection(chatCollection).FindOne(ctx, filter).Decode(&chat); err != nil {
		return nil, status.Errorf(
			codes.NotFound, "chat id does not exist",
		)
	}
	return &chat, nil
}

// HasMember checks if a chat has a member.
func HasMember(members []primitive.ObjectID, userID primitive.ObjectID) bool {
	for _, e := range members {
		if e == userID {
			return true
		}
	}
	return false
}

// Create inserts a new group chat into the database.
func (c Group) Create(ctx context.Context, db *mongo.Database) (*Group, error) {
	result, err := db.Collection(chatCollection).InsertOne(ctx, c)
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "creating group chat",
		)
	}
	c.ID = result.InsertedID.(primitive.ObjectID)
	return &c, nil
}

// Create inserts a new individual chat into the database.
func (c Individual) Create(ctx context.Context, db *mongo.Database) (*Individual, error) {
	result, err := db.Collection(chatCollection).InsertOne(ctx, c)
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "creating individual chat",
		)
	}
	c.ID = result.InsertedID.(primitive.ObjectID)
	return &c, nil
}

// AddMember adds a member to a group chat.
func AddMember(ctx context.Context, db *mongo.Database, chatID primitive.ObjectID, userID primitive.ObjectID) (*Group, error) {
	var chat Group
	filter := bson.M{"_id": chatID}
	update := bson.M{"$push": bson.M{"members": userID}}
	if err := db.Collection(chatCollection).FindOneAndUpdate(ctx, filter, update).Decode(&chat); err != nil {
		return nil, status.Errorf(
			codes.Internal, "adding member to group chat",
		)
	}
	return &chat, nil
}

// Exists checks if an individual chat exists.
func (c Individual) Exists(ctx context.Context, db *mongo.Database) bool {
	var chat Individual
	filter := bson.M{"type": c.Type, "members": bson.M{"$all": bson.A{c.Members[0], c.Members[1]}}}
	if err := db.Collection(chatCollection).FindOne(ctx, filter).Decode(&chat); err != nil {
		return false
	}
	return true
}
