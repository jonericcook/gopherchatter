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

// GetChat checks if a user exists.
func GetChat(ctx context.Context, db *mongo.Database, chatID primitive.ObjectID) (*Chat, error) {
	var chat Chat
	if err := db.Collection(groupChatCollection).FindOne(ctx, bson.M{"_id": chatID}).Decode(&chat); err != nil {
		return nil, status.Errorf(
			codes.NotFound, "chat id does not exist",
		)
	}
	return &chat, nil
}

// ChatHasMember checks if a chat has a member.
func ChatHasMember(chat *Chat, userID primitive.ObjectID) bool {
	for _, e := range chat.Members {
		if e == userID {
			return true
		}
	}
	return false
}

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

// AddMemberToChat adds a member to a chat.
func AddMemberToChat(ctx context.Context, db *mongo.Database, chatID primitive.ObjectID, userID primitive.ObjectID) (*Chat, error) {
	var chat Chat
	if err := db.Collection(groupChatCollection).FindOneAndUpdate(ctx, bson.M{"_id": chatID}, bson.M{"$push": bson.M{"members": userID}}).Decode(&chat); err != nil {
		return nil, status.Errorf(
			codes.Internal, "adding to group chat",
		)
	}
	return &chat, nil
}
