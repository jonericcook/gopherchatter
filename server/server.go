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
	users           *mongo.Collection
	friends         *mongo.Collection
	individualChats *mongo.Collection
	groupChats      *mongo.Collection
	messages        *mongo.Collection
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
	if claims["sub"] != req.GetCreatorId() {
		return nil, status.Errorf(
			codes.InvalidArgument, "subject in token must match creator_id",
		)
	}
	creatorID, err := primitive.ObjectIDFromHex(req.GetCreatorId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	result, err := gcs.groupChats.InsertOne(ctx, bson.D{
		{Key: "chat_name", Value: req.GetChatName()},
		{Key: "creator_id", Value: creatorID},
	})
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "internal error",
		)
	}
	return &gopherchatterv0.CreateGroupChatResponse{
		ChatId:    result.InsertedID.(primitive.ObjectID).Hex(),
		ChatName:  req.GetChatName(),
		CreatorId: req.GetCreatorId(),
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
		users:           db.Collection("users"),
		friends:         db.Collection("friends"),
		individualChats: db.Collection("individualchats"),
		groupChats:      db.Collection("groupchats"),
		messages:        db.Collection("messages"),
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
