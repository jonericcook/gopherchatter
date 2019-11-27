package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/golang/protobuf/ptypes/empty"
	gopherchatterv0 "github.com/jonericcook/gopherchatter/v0"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
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
	mySigningKey := []byte("gopherchatter")
	claims := &jwt.StandardClaims{
		Subject:   data.UserID.String(),
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(mySigningKey)
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

func main() {
	client, err := mongo.NewClient(options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = client.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(ctx)

	db := client.Database("gopherchatter")

	listener, err := net.Listen("tcp", "0.0.0.0:50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	gcs := gopherChatterServer{
		users:           db.Collection("users"),
		friends:         db.Collection("friends"),
		individualChats: db.Collection("individualchats"),
		groupChats:      db.Collection("groupchats"),
		messages:        db.Collection("messages"),
	}
	gopherchatterv0.RegisterGopherChatterServer(s, &gcs)
	fmt.Println("gRPC server started on 0.0.0.0:50051")
	if err := s.Serve(listener); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
