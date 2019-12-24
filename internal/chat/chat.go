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

// GetGroup checks if a group chat exists and if it does, returns it.
func GetGroup(ctx context.Context, db *mongo.Database, chatID primitive.ObjectID) (*Group, error) {
	var chat Group
	filter := bson.M{"_id": chatID, "type": GroupLabel}
	if err := db.Collection(chatCollection).FindOne(ctx, filter).Decode(&chat); err != nil {
		return nil, status.Errorf(
			codes.NotFound, "chat id does not exist",
		)
	}
	return &chat, nil
}

// GetGroups returns all the group chats per a user.
func GetGroups(ctx context.Context, db *mongo.Database, userID primitive.ObjectID) ([]Group, error) {
	filter := bson.M{"type": GroupLabel, "members": userID}
	cursor, err := db.Collection(chatCollection).Find(ctx, filter)
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "getting group chats",
		)
	}
	var groups []Group
	if err = cursor.All(ctx, &groups); err != nil {
		return nil, status.Errorf(
			codes.InvalidArgument, "getting group chats from cursor",
		)
	}
	return groups, nil
}

// GetIndividual checks if a individual chat exists and if it does, returns it.
func GetIndividual(ctx context.Context, db *mongo.Database, chatID primitive.ObjectID) (*Individual, error) {
	var chat Individual
	filter := bson.M{"_id": chatID, "type": IndividualLabel}
	if err := db.Collection(chatCollection).FindOne(ctx, filter).Decode(&chat); err != nil {
		return nil, status.Errorf(
			codes.NotFound, "chat id does not exist",
		)
	}
	return &chat, nil
}

// GetIndividuals returns all the group chats per a user.
func GetIndividuals(ctx context.Context, db *mongo.Database, userID primitive.ObjectID) ([]Individual, error) {
	filter := bson.M{"type": IndividualLabel, "members": userID}
	cursor, err := db.Collection(chatCollection).Find(ctx, filter)
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "getting individual chats",
		)
	}
	var individuals []Individual
	if err = cursor.All(ctx, &individuals); err != nil {
		return nil, status.Errorf(
			codes.InvalidArgument, "getting individual chats from cursor",
		)
	}
	return individuals, nil
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

// DeleteGroup deletes a group chat.
func DeleteGroup(ctx context.Context, db *mongo.Database, chatID primitive.ObjectID) error {
	filter := bson.M{"_id": chatID}
	_, err := db.Collection(chatCollection).DeleteOne(ctx, filter)
	if err != nil {
		return status.Errorf(
			codes.Internal, "deleteing group chat",
		)
	}
	return nil
}

// UpdateGroupChatAdmin updates the admin of a group chat.
func UpdateGroupChatAdmin(ctx context.Context, db *mongo.Database, chatID primitive.ObjectID, userID primitive.ObjectID) error {
	var chat Group
	filter := bson.M{"_id": chatID, "type": GroupLabel}
	update := bson.M{"$set": bson.M{"admin": userID}}
	if err := db.Collection(chatCollection).FindOneAndUpdate(ctx, filter, update).Decode(&chat); err != nil {
		return status.Errorf(
			codes.Internal, "updating group chat admin",
		)
	}
	return nil
}

// AddGroupChatMember adds a member to a group chat.
func AddGroupChatMember(ctx context.Context, db *mongo.Database, chatID primitive.ObjectID, userID primitive.ObjectID) error {
	var chat Group
	filter := bson.M{"_id": chatID, "type": GroupLabel}
	update := bson.M{"$push": bson.M{"members": userID}}
	if err := db.Collection(chatCollection).FindOneAndUpdate(ctx, filter, update).Decode(&chat); err != nil {
		return status.Errorf(
			codes.Internal, "adding member to group chat",
		)
	}
	return nil
}

// RemoveGroupChatMember adds a member to a chat.
func RemoveGroupChatMember(ctx context.Context, db *mongo.Database, chatID primitive.ObjectID, userID primitive.ObjectID) error {
	var chat Group
	filter := bson.M{"_id": chatID, "type": GroupLabel}
	update := bson.M{"$pull": bson.M{"members": userID}}
	if err := db.Collection(chatCollection).FindOneAndUpdate(ctx, filter, update).Decode(&chat); err != nil {
		return status.Errorf(
			codes.Internal, "removing member from group chat",
		)
	}
	return nil
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

// IndividualChatExists checks if an individual chat exists.
func IndividualChatExists(ctx context.Context, db *mongo.Database, m0 primitive.ObjectID, m1 primitive.ObjectID) bool {
	var chat Individual
	filter := bson.M{"type": IndividualLabel, "members": bson.M{"$all": bson.A{m0, m1}}}
	if err := db.Collection(chatCollection).FindOne(ctx, filter).Decode(&chat); err != nil {
		return false
	}
	return true
}
