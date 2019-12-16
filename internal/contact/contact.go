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

// Exists checks if a contact already exists.
func Exists(ctx context.Context, db *mongo.Database, c Contact) bool {
	var contact Contact
	filter := bson.M{"owner": c.Owner, "user": c.User}
	if err := db.Collection(contactsCollection).FindOne(ctx, filter).Decode(&contact); err != nil {
		return false
	}
	return true
}

// GetAll returns all a user's contacts.
func GetAll(ctx context.Context, db *mongo.Database, userID primitive.ObjectID) ([]Contact, error) {
	filter := bson.M{"owner": userID}
	cursor, err := db.Collection(contactsCollection).Find(ctx, filter)
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "getting contacts",
		)
	}
	var contacts []Contact
	if err = cursor.All(ctx, &contacts); err != nil {
		return nil, status.Errorf(
			codes.InvalidArgument, "getting contacts from cursor",
		)
	}
	return contacts, nil
}

// Add inserts a new contact into the database for the specified user.
func Add(ctx context.Context, db *mongo.Database, c Contact) (*Contact, error) {
	result, err := db.Collection(contactsCollection).InsertOne(ctx, c)
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "adding contact",
		)
	}
	c.ID = result.InsertedID.(primitive.ObjectID)
	return &c, nil
}
