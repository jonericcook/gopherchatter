package contact

import (
	"context"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const contactsCollection = "contacts"

// Add inserts a new contact into the database for the specified user.
func Add(ctx context.Context, db *mongo.Database, c Contact) (*Contact, error) {
	var contact Contact
	if err := db.Collection(contactsCollection).FindOne(ctx, bson.M{"owner_id": c.OwnerID, "user_id": c.UserID}).Decode(&contact); err == nil {
		return nil, status.Errorf(
			codes.NotFound, "contact already exists",
		)
	}
	result, err := db.Collection(contactsCollection).InsertOne(ctx, c)
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	c.ID = result.InsertedID.(primitive.ObjectID)
	return &c, nil
}
