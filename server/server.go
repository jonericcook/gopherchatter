package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/golang/protobuf/ptypes/empty"
	gopherchatterv0 "github.com/jonericcook/gopherchatter/v0"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type gopherChatterServer struct {
	users                  *mongo.Collection
	contacts               *mongo.Collection
	individualChats        *mongo.Collection
	individualChatMessages *mongo.Collection
	groupChats             *mongo.Collection
	groupChatMessages      *mongo.Collection
}

func (gcs *gopherChatterServer) CreateUser(ctx context.Context, req *gopherchatterv0.CreateUserRequest) (*empty.Empty, error) {
	var user bson.M
	if err := gcs.users.FindOne(ctx, bson.M{"username": req.GetUsername()}).Decode(&user); err == nil {
		return nil, status.Errorf(
			codes.AlreadyExists, "username already exists",
		)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.GetPassword()), bcrypt.DefaultCost)
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	_, err = gcs.users.InsertOne(ctx, bson.D{
		{Key: "username", Value: req.GetUsername()},
		{Key: "password_hash", Value: hash},
	})
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	return &empty.Empty{}, nil
}

func (gcs *gopherChatterServer) Authenticate(ctx context.Context, req *gopherchatterv0.AuthenticateRequest) (*gopherchatterv0.AuthenticateResponse, error) {
	var data struct {
		UserID       primitive.ObjectID `bson:"_id"`
		Username     string             `bson:"username"`
		PasswordHash []byte             `bson:"password_hash"`
	}
	if err := gcs.users.FindOne(ctx, bson.M{"username": req.GetUsername()}).Decode(&data); err != nil {
		return nil, status.Errorf(
			codes.InvalidArgument, "username or password is incorrect",
		)
	}
	if err := bcrypt.CompareHashAndPassword(data.PasswordHash, []byte(req.GetPassword())); err != nil {
		return nil, status.Errorf(
			codes.InvalidArgument, "username or password is incorrect",
		)
	}
	signingKey := []byte("gopherchatter")
	claims := &jwt.StandardClaims{
		Subject:   data.UserID.Hex(),
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(12 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(signingKey)
	if err != nil {
		return nil, status.Errorf(
			codes.Unauthenticated, "username or password is incorrect",
		)
	}
	return &gopherchatterv0.AuthenticateResponse{
		UserId:   data.UserID.Hex(),
		Username: data.Username,
		Token:    ss,
	}, nil
}

func (gcs *gopherChatterServer) CreateGroupChat(ctx context.Context, req *gopherchatterv0.CreateGroupChatRequest) (*gopherchatterv0.CreateGroupChatResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	tokenString := strings.TrimPrefix(md["authorization"][0], "Bearer ")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, status.Errorf(
				codes.Internal, "internal error",
			)
		}
		return []byte("gopherchatter"), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok && !token.Valid {
		return nil, status.Errorf(
			codes.Unauthenticated, "invalid token",
		)
	}
	if claims["sub"] != req.GetAdminId() {
		return nil, status.Errorf(
			codes.InvalidArgument, "subject in token must match admin_id",
		)
	}
	adminID, err := primitive.ObjectIDFromHex(req.GetAdminId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	result, err := gcs.groupChats.InsertOne(ctx, bson.D{
		{Key: "chat_name", Value: req.GetChatName()},
		{Key: "admin_id", Value: adminID},
		{Key: "member_ids", Value: bson.A{adminID}},
	})
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	return &gopherchatterv0.CreateGroupChatResponse{
		ChatId:    result.InsertedID.(primitive.ObjectID).Hex(),
		ChatName:  req.GetChatName(),
		AdminId:   req.GetAdminId(),
		MemberIds: []string{req.GetAdminId()},
	}, nil
}

func (gcs *gopherChatterServer) AddContact(ctx context.Context, req *gopherchatterv0.AddContactRequest) (*empty.Empty, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	tokenString := strings.TrimPrefix(md["authorization"][0], "Bearer ")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, status.Errorf(
				codes.Internal, "internal error",
			)
		}
		return []byte("gopherchatter"), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok && !token.Valid {
		return nil, status.Errorf(
			codes.Unauthenticated, "invalid token",
		)
	}
	if claims["sub"] != req.GetUserId() {
		return nil, status.Errorf(
			codes.InvalidArgument, "subject in token must match user_id",
		)
	}
	contactID, err := primitive.ObjectIDFromHex(req.GetContactId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	userID, err := primitive.ObjectIDFromHex(req.GetUserId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	var user bson.M
	if err := gcs.users.FindOne(ctx, bson.M{"_id": contactID}).Decode(&user); err != nil {
		return nil, status.Errorf(
			codes.NotFound, "user not found",
		)
	}

	var contact bson.M
	if err := gcs.contacts.FindOne(ctx, bson.M{"user_id": userID, "contact_id": contactID}).Decode(&contact); err == nil {
		return nil, status.Errorf(
			codes.NotFound, "already have as contact",
		)
	}
	_, err = gcs.contacts.InsertOne(ctx, bson.D{
		{Key: "user_id", Value: userID},
		{Key: "contact_id", Value: contactID},
	})
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	return &empty.Empty{}, nil
}

func (gcs *gopherChatterServer) RemoveContact(ctx context.Context, req *gopherchatterv0.RemoveContactRequest) (*empty.Empty, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	tokenString := strings.TrimPrefix(md["authorization"][0], "Bearer ")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, status.Errorf(
				codes.Internal, "internal error",
			)
		}
		return []byte("gopherchatter"), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok && !token.Valid {
		return nil, status.Errorf(
			codes.Unauthenticated, "invalid token",
		)
	}
	if claims["sub"] != req.GetUserId() {
		return nil, status.Errorf(
			codes.InvalidArgument, "subject in token must match user_id",
		)
	}
	contactID, err := primitive.ObjectIDFromHex(req.GetContactId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	userID, err := primitive.ObjectIDFromHex(req.GetUserId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	var user bson.M
	if err := gcs.users.FindOne(ctx, bson.M{"_id": contactID}).Decode(&user); err != nil {
		return nil, status.Errorf(
			codes.NotFound, "user not found",
		)
	}
	if gcs.contacts.FindOneAndDelete(ctx, bson.M{"user_id": userID, "contact_id": contactID}).Err() != nil {
		return nil, status.Errorf(
			codes.NotFound, "contact not found",
		)
	}
	return &empty.Empty{}, nil
}
func (gcs *gopherChatterServer) AddContactToGroupChat(ctx context.Context, req *gopherchatterv0.AddContactToGroupChatRequest) (*empty.Empty, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	tokenString := strings.TrimPrefix(md["authorization"][0], "Bearer ")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, status.Errorf(
				codes.Internal, "internal error",
			)
		}
		return []byte("gopherchatter"), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok && !token.Valid {
		return nil, status.Errorf(
			codes.Unauthenticated, "invalid token",
		)
	}
	if claims["sub"] != req.GetAdminId() {
		return nil, status.Errorf(
			codes.InvalidArgument, "subject in token must match admin_id",
		)
	}
	contactID, err := primitive.ObjectIDFromHex(req.GetContactId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	adminID, err := primitive.ObjectIDFromHex(req.GetAdminId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	chatID, err := primitive.ObjectIDFromHex(req.GetChatId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	var user bson.M
	if err := gcs.users.FindOne(ctx, bson.M{"_id": contactID}).Decode(&user); err != nil {
		return nil, status.Errorf(
			codes.NotFound, "user not found",
		)
	}
	var contact bson.M
	if err := gcs.contacts.FindOne(ctx, bson.M{"user_id": adminID, "contact_id": contactID}).Decode(&contact); err != nil {
		return nil, status.Errorf(
			codes.NotFound, "not a contact",
		)
	}
	if err := gcs.groupChats.FindOne(ctx, bson.M{"_id": chatID, "admin_id": adminID, "member_ids": contactID}).Decode(&contact); err == nil {
		return nil, status.Errorf(
			codes.InvalidArgument, "contact is already in group chat",
		)
	}
	var updatedDocument bson.M
	if err := gcs.groupChats.FindOneAndUpdate(ctx, bson.M{"_id": chatID, "admin_id": adminID, "member_ids": adminID}, bson.M{"$push": bson.M{"member_ids": contactID}}).Decode(&updatedDocument); err != nil {
		return nil, status.Errorf(
			codes.Internal, "could not add to group chat",
		)
	}
	return &empty.Empty{}, nil
}

func (gcs *gopherChatterServer) RemoveContactFromGroupChat(ctx context.Context, req *gopherchatterv0.RemoveContactFromGroupChatRequest) (*empty.Empty, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	tokenString := strings.TrimPrefix(md["authorization"][0], "Bearer ")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, status.Errorf(
				codes.Internal, "internal error",
			)
		}
		return []byte("gopherchatter"), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok && !token.Valid {
		return nil, status.Errorf(
			codes.Unauthenticated, "invalid token",
		)
	}
	if claims["sub"] != req.GetAdminId() {
		return nil, status.Errorf(
			codes.InvalidArgument, "subject in token must match admin_id",
		)
	}
	contactID, err := primitive.ObjectIDFromHex(req.GetContactId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	adminID, err := primitive.ObjectIDFromHex(req.GetAdminId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	chatID, err := primitive.ObjectIDFromHex(req.GetChatId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	var user bson.M
	if err := gcs.users.FindOne(ctx, bson.M{"_id": contactID}).Decode(&user); err != nil {
		return nil, status.Errorf(
			codes.NotFound, "user not found",
		)
	}
	var contact bson.M
	if err := gcs.groupChats.FindOne(ctx, bson.M{"_id": chatID, "admin_id": adminID, "member_ids": contactID}).Decode(&contact); err != nil {
		return nil, status.Errorf(
			codes.InvalidArgument, "contact not in group chat",
		)
	}
	var updatedDocument bson.M
	if err := gcs.groupChats.FindOneAndUpdate(ctx, bson.M{"_id": chatID, "admin_id": adminID, "member_ids": adminID}, bson.M{"$pull": bson.M{"member_ids": contactID}}).Decode(&updatedDocument); err != nil {
		return nil, status.Errorf(
			codes.Internal, "could not remove contact from group chat",
		)
	}
	return &empty.Empty{}, nil
}

func (gcs *gopherChatterServer) SendMessageToGroupChat(ctx context.Context, req *gopherchatterv0.SendMessageToGroupChatRequest) (*gopherchatterv0.SendMessageToGroupChatResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	tokenString := strings.TrimPrefix(md["authorization"][0], "Bearer ")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, status.Errorf(
				codes.Internal, "internal error",
			)
		}
		return []byte("gopherchatter"), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok && !token.Valid {
		return nil, status.Errorf(
			codes.Unauthenticated, "invalid token",
		)
	}
	if claims["sub"] != req.GetAuthorId() {
		return nil, status.Errorf(
			codes.InvalidArgument, "subject in token must match author_id",
		)
	}
	authorID, err := primitive.ObjectIDFromHex(req.GetAuthorId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	chatID, err := primitive.ObjectIDFromHex(req.GetChatId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	var user bson.M
	if err := gcs.users.FindOne(ctx, bson.M{"_id": authorID}).Decode(&user); err != nil {
		return nil, status.Errorf(
			codes.NotFound, "user not found",
		)
	}
	var groupChat bson.M
	if err := gcs.groupChats.FindOne(ctx, bson.M{"_id": chatID, "member_ids": authorID}).Decode(&groupChat); err != nil {
		return nil, status.Errorf(
			codes.InvalidArgument, "not in group chat",
		)
	}
	createdTimestamp := primitive.NewObjectID().Timestamp()
	result, err := gcs.groupChatMessages.InsertOne(ctx, bson.D{
		{Key: "chat_id", Value: chatID},
		{Key: "author_id", Value: authorID},
		{Key: "content", Value: req.GetContent()},
		{Key: "created_timestamp", Value: createdTimestamp},
	})
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	return &gopherchatterv0.SendMessageToGroupChatResponse{
		MessageId: result.InsertedID.(primitive.ObjectID).Hex(),
		ChatId:    req.GetChatId(),
		AuthorId:  req.GetAuthorId(),
		Content:   req.GetContent(),
	}, nil

}

func (gcs *gopherChatterServer) CreateIndividualChat(ctx context.Context, req *gopherchatterv0.CreateIndividualChatRequest) (*gopherchatterv0.CreateIndividualChatResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	tokenString := strings.TrimPrefix(md["authorization"][0], "Bearer ")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, status.Errorf(
				codes.Internal, "internal error",
			)
		}
		return []byte("gopherchatter"), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok && !token.Valid {
		return nil, status.Errorf(
			codes.Unauthenticated, "invalid token",
		)
	}
	userID, err := primitive.ObjectIDFromHex(claims["sub"].(string))
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	withUserID, err := primitive.ObjectIDFromHex(req.GetWithUserId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	var user bson.M
	if err := gcs.users.FindOne(ctx, bson.M{"_id": withUserID}).Decode(&user); err != nil {
		return nil, status.Errorf(
			codes.NotFound, "user not found",
		)
	}
	var contact bson.M
	if err := gcs.contacts.FindOne(ctx, bson.M{"user_id": userID, "contact_id": withUserID}).Decode(&contact); err != nil {
		return nil, status.Errorf(
			codes.NotFound, "not a contact",
		)
	}
	result, err := gcs.individualChats.InsertOne(ctx, bson.D{
		{Key: "member_ids", Value: bson.A{userID, withUserID}},
	})
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	return &gopherchatterv0.CreateIndividualChatResponse{
		ChatId:    result.InsertedID.(primitive.ObjectID).Hex(),
		MemberIds: []string{claims["sub"].(string), req.GetWithUserId()},
	}, nil
}

func (gcs *gopherChatterServer) SendMessageToIndiviualChat(ctx context.Context, req *gopherchatterv0.SendMessageToIndividualChatRequest) (*gopherchatterv0.SendMessageToIndividualChatResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	tokenString := strings.TrimPrefix(md["authorization"][0], "Bearer ")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, status.Errorf(
				codes.Internal, "internal error",
			)
		}
		return []byte("gopherchatter"), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok && !token.Valid {
		return nil, status.Errorf(
			codes.Unauthenticated, "invalid token",
		)
	}
	if claims["sub"] != req.GetAuthorId() {
		return nil, status.Errorf(
			codes.InvalidArgument, "subject in token must match author_id",
		)
	}
	authorID, err := primitive.ObjectIDFromHex(req.GetAuthorId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	chatID, err := primitive.ObjectIDFromHex(req.GetChatId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	var user bson.M
	if err := gcs.users.FindOne(ctx, bson.M{"_id": authorID}).Decode(&user); err != nil {
		return nil, status.Errorf(
			codes.NotFound, "user not found",
		)
	}
	var individualChat bson.M
	if err := gcs.individualChats.FindOne(ctx, bson.M{"_id": chatID, "member_ids": authorID}).Decode(&individualChat); err != nil {
		return nil, status.Errorf(
			codes.InvalidArgument, "not in individual chat",
		)
	}
	createdTimestamp := primitive.NewObjectID().Timestamp()
	result, err := gcs.individualChatMessages.InsertOne(ctx, bson.D{
		{Key: "chat_id", Value: chatID},
		{Key: "author_id", Value: authorID},
		{Key: "content", Value: req.GetContent()},
		{Key: "created_timestamp", Value: createdTimestamp},
	})
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	return &gopherchatterv0.SendMessageToIndividualChatResponse{
		MessageId: result.InsertedID.(primitive.ObjectID).Hex(),
		ChatId:    req.GetChatId(),
		AuthorId:  req.GetAuthorId(),
		Content:   req.GetContent(),
	}, nil
}

func (gcs *gopherChatterServer) GetContactsList(ctx context.Context, req *gopherchatterv0.GetContactsListRequest) (*gopherchatterv0.GetContactsListResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	tokenString := strings.TrimPrefix(md["authorization"][0], "Bearer ")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, status.Errorf(
				codes.Internal, "internal error",
			)
		}
		return []byte("gopherchatter"), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok && !token.Valid {
		return nil, status.Errorf(
			codes.Unauthenticated, "invalid token",
		)
	}
	if claims["sub"] != req.GetUserId() {
		return nil, status.Errorf(
			codes.InvalidArgument, "subject in token must match user_id",
		)
	}
	userID, err := primitive.ObjectIDFromHex(req.GetUserId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	var user bson.M
	if err := gcs.users.FindOne(ctx, bson.M{"_id": userID}).Decode(&user); err != nil {
		return nil, status.Errorf(
			codes.NotFound, "user not found",
		)
	}
	opts := options.Find().SetSort(bson.D{{Key: "user_name", Value: 1}})
	cursor, err := gcs.contacts.Find(ctx, bson.M{"user_id": userID}, opts)
	if err != nil {
		return nil, status.Errorf(
			codes.InvalidArgument, "not in individual chat",
		)
	}
	var result []bson.M
	if err = cursor.All(ctx, &result); err != nil {
		return nil, status.Errorf(
			codes.InvalidArgument, "not in individual chat",
		)
	}
	var contacts []*gopherchatterv0.Contact
	for i := range result {
		var user bson.M
		if err := gcs.users.FindOne(ctx, bson.M{"_id": result[i]["contact_id"]}).Decode(&user); err != nil {
			return nil, status.Errorf(
				codes.NotFound, "user not found",
			)
		}
		userID := result[i]["contact_id"].(primitive.ObjectID).Hex()
		userName := user["username"].(string)
		c := gopherchatterv0.Contact{
			UserId:   userID,
			UserName: userName,
		}
		contacts = append(contacts, &c)
	}
	return &gopherchatterv0.GetContactsListResponse{
		UserId:   req.GetUserId(),
		Contacts: contacts,
	}, nil
}

func (gcs *gopherChatterServer) GetIndividualChats(ctx context.Context, req *gopherchatterv0.GetIndividualChatsRequest) (*gopherchatterv0.GetIndividualChatsResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	tokenString := strings.TrimPrefix(md["authorization"][0], "Bearer ")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, status.Errorf(
				codes.Internal, "internal error",
			)
		}
		return []byte("gopherchatter"), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok && !token.Valid {
		return nil, status.Errorf(
			codes.Unauthenticated, "invalid token",
		)
	}
	if claims["sub"] != req.GetUserId() {
		return nil, status.Errorf(
			codes.InvalidArgument, "subject in token must match user_id",
		)
	}
	userID, err := primitive.ObjectIDFromHex(req.GetUserId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	var user bson.M
	if err := gcs.users.FindOne(ctx, bson.M{"_id": userID}).Decode(&user); err != nil {
		return nil, status.Errorf(
			codes.NotFound, "user not found",
		)
	}
	cursor, err := gcs.individualChats.Find(ctx, bson.M{"member_ids": userID})
	if err != nil {
		return nil, status.Errorf(
			codes.InvalidArgument, "not in individual chat",
		)
	}
	var result []bson.M
	if err = cursor.All(ctx, &result); err != nil {
		return nil, status.Errorf(
			codes.InvalidArgument, "not in individual chat",
		)
	}
	var chatIDs []string
	for _, e := range result {
		chatIDs = append(chatIDs, e["_id"].(primitive.ObjectID).Hex())
	}
	return &gopherchatterv0.GetIndividualChatsResponse{
		UserId:  req.GetUserId(),
		ChatIds: chatIDs,
	}, nil
}

func (gcs *gopherChatterServer) GetGroupChats(ctx context.Context, req *gopherchatterv0.GetGroupChatsRequest) (*gopherchatterv0.GetGroupChatsResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	tokenString := strings.TrimPrefix(md["authorization"][0], "Bearer ")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, status.Errorf(
				codes.Internal, "internal error",
			)
		}
		return []byte("gopherchatter"), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok && !token.Valid {
		return nil, status.Errorf(
			codes.Unauthenticated, "invalid token",
		)
	}
	if claims["sub"] != req.GetUserId() {
		return nil, status.Errorf(
			codes.InvalidArgument, "subject in token must match user_id",
		)
	}
	userID, err := primitive.ObjectIDFromHex(req.GetUserId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	var user bson.M
	if err := gcs.users.FindOne(ctx, bson.M{"_id": userID}).Decode(&user); err != nil {
		return nil, status.Errorf(
			codes.NotFound, "user not found",
		)
	}
	cursor, err := gcs.groupChats.Find(ctx, bson.M{"member_ids": userID})
	if err != nil {
		return nil, status.Errorf(
			codes.InvalidArgument, "not in group chat",
		)
	}
	var result []bson.M
	if err = cursor.All(ctx, &result); err != nil {
		return nil, status.Errorf(
			codes.InvalidArgument, "not in group chat",
		)
	}
	var chatIDs []string
	for _, e := range result {
		chatIDs = append(chatIDs, e["_id"].(primitive.ObjectID).Hex())
	}
	return &gopherchatterv0.GetGroupChatsResponse{
		UserId:  req.GetUserId(),
		ChatIds: chatIDs,
	}, nil
}

func main() {
	mongoClient, err := mongo.NewClient(options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Fatal(err)
	}
	mongoCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = mongoClient.Connect(mongoCtx)
	if err != nil {
		log.Fatal(err)
	}
	defer mongoClient.Disconnect(mongoCtx)
	err = mongoClient.Ping(mongoCtx, readpref.Primary())
	if err != nil {
		log.Fatalf("mongodb could not be reached: %v", err)
	}
	fmt.Println("connected to MongoDB at localhost:27017")

	db := mongoClient.Database("gopherchatter")

	listener, err := net.Listen("tcp", "localhost:50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	grpcs := grpc.NewServer()
	gcs := gopherChatterServer{
		users:                  db.Collection("users"),
		contacts:               db.Collection("contacts"),
		individualChats:        db.Collection("individualchats"),
		groupChats:             db.Collection("groupchats"),
		groupChatMessages:      db.Collection("groupchatmessages"),
		individualChatMessages: db.Collection("individualchatmessages"),
	}
	gopherchatterv0.RegisterGopherChatterServer(grpcs, &gcs)
	go func() {
		if err := grpcs.Serve(listener); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()
	fmt.Println("gRPC server started at localhost:50051")

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	<-shutdown
	fmt.Println("\nstopping gRPC server")
	grpcs.Stop()
	listener.Close()
	fmt.Println("closing MongoDB connection")
	mongoClient.Disconnect(mongoCtx)
}
