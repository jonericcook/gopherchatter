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

// GetGroup checks if a group chat exists.
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

// GetIndividual checks if a individual chat exists.
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

// IsMember checks if a chat has a member.
func IsMember(members []primitive.ObjectID, userID primitive.ObjectID) bool {
	for _, e := range members {
		if e == userID {
			return true
		}
	}
	return false
}

// CreateGroup inserts a new group chat into the database.
func CreateGroup(ctx context.Context, db *mongo.Database, c Group) (*Group, error) {
	result, err := db.Collection(chatCollection).InsertOne(ctx, c)
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "creating group chat",
		)
	}
	c.ID = result.InsertedID.(primitive.ObjectID)
	return &c, nil
}

// CreateIndividual inserts a new individual chat into the database.
func CreateIndividual(ctx context.Context, db *mongo.Database, c Individual) (*Individual, error) {
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
func (c Group) AddMember(ctx context.Context, db *mongo.Database, userID primitive.ObjectID) error {
	var chat Group
	filter := bson.M{"_id": c.ID}
	update := bson.M{"$push": bson.M{"members": userID}}
	if err := db.Collection(chatCollection).FindOneAndUpdate(ctx, filter, update).Decode(&chat); err != nil {
		return status.Errorf(
			codes.Internal, "adding member to group chat",
		)
	}
	return nil
}

// RemoveMember adds a member to a chat.
func (c Group) RemoveMember(ctx context.Context, db *mongo.Database, userID primitive.ObjectID) error {
	var chat Group
	filter := bson.M{"_id": c.ID}
	update := bson.M{"$pull": bson.M{"members": userID}}
	if err := db.Collection(chatCollection).FindOneAndUpdate(ctx, filter, update).Decode(&chat); err != nil {
		return status.Errorf(
			codes.Internal, "removing member from group chat",
		)
	}
	return nil
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
