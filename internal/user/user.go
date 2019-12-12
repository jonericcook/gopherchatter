package user

import (
	"context"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const usersCollection = "users"

// Create inserts a new user into the database.
func Create(ctx context.Context, db *mongo.Database, nu NewUser) (*User, error) {
	if len(nu.Username) < 1 {
		return nil, status.Errorf(
			codes.InvalidArgument, "name must be at least 1 character",
		)
	}
	if len(nu.Username) > 12 {
		return nil, status.Errorf(
			codes.InvalidArgument, "name must be at max 12 characters",
		)
	}
	var foundNonLowerCaseInUsernane bool
	for _, c := range nu.Username {
		if int(c) < 97 || int(c) > 122 {
			foundNonLowerCaseInUsernane = true
		}
	}
	if foundNonLowerCaseInUsernane {
		return nil, status.Errorf(
			codes.InvalidArgument, "name must only contain lowercase characters",
		)
	}
	if len(nu.Password) < 8 {
		return nil, status.Errorf(
			codes.InvalidArgument, "password must be at least 8 characters",
		)
	}
	if len(nu.Password) > 64 {
		return nil, status.Errorf(
			codes.InvalidArgument, "password must be at max 64 characters",
		)
	}
	var foundLowerInPassword bool
	var foundUpperInPassword bool
	var foundNumberInPassword bool
	var foundSpecialInPassword bool
	for _, c := range nu.Password {
		if int(c) >= 65 && int(c) <= 90 {
			foundUpperInPassword = true
		}
		if int(c) >= 97 && int(c) <= 122 {
			foundLowerInPassword = true
		}
		if int(c) >= 48 && int(c) <= 57 {
			foundNumberInPassword = true
		}
		if (int(c) >= 32 && int(c) <= 47) ||
			(int(c) >= 58 && int(c) <= 64) ||
			(int(c) >= 91 && int(c) <= 96) ||
			(int(c) >= 123 && int(c) <= 126) {
			foundSpecialInPassword = true
		}
	}
	if !foundLowerInPassword {
		return nil, status.Errorf(
			codes.InvalidArgument, "password must contain at least one lowercase character",
		)
	}
	if !foundUpperInPassword {
		return nil, status.Errorf(
			codes.InvalidArgument, "password must contain at least one uppercase character",
		)
	}
	if !foundNumberInPassword {
		return nil, status.Errorf(
			codes.InvalidArgument, "password must contain at least one number",
		)
	}
	if !foundSpecialInPassword {
		return nil, status.Errorf(
			codes.InvalidArgument, "password must contain at least one special character",
		)
	}
	if nu.Password != nu.PasswordConfirm {
		return nil, status.Errorf(
			codes.InvalidArgument, "password and password_confirm must match",
		)
	}
	var user User
	if err := db.Collection(usersCollection).FindOne(ctx, bson.M{"username": nu.Username}).Decode(&user); err == nil {
		return nil, status.Errorf(
			codes.AlreadyExists, "name already exists",
		)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(nu.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	u := User{
		Username:     nu.Username,
		PasswordHash: string(hash),
	}
	result, err := db.Collection(usersCollection).InsertOne(ctx, u)
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	u.ID = result.InsertedID.(primitive.ObjectID)
	return &u, nil
}

// Authenticate authenticates a user based on their username and password
func Authenticate(ctx context.Context, db *mongo.Database, uc Credentials) (*User, error) {
	var u User
	if err := db.Collection(usersCollection).FindOne(ctx, bson.M{"username": uc.Username}).Decode(&u); err != nil {
		return nil, status.Errorf(
			codes.Unauthenticated, "username or password is incorrect",
		)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(uc.Password)); err != nil {
		return nil, status.Errorf(
			codes.Unauthenticated, "username or password is incorrect",
		)
	}
	return &u, nil
}
