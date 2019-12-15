package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ardanlabs/conf"
	"github.com/dgrijalva/jwt-go"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	"github.com/jonericcook/gopherchatter/internal/contact"
	"github.com/jonericcook/gopherchatter/internal/group"
	"github.com/jonericcook/gopherchatter/internal/individual"
	"github.com/jonericcook/gopherchatter/internal/middleware"
	"github.com/jonericcook/gopherchatter/internal/platform/database"
	gopherchatterv0 "github.com/jonericcook/gopherchatter/internal/platform/protobuf/v0"
	"github.com/jonericcook/gopherchatter/internal/user"
	"github.com/pkg/errors"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ========================================================================================
// Authentication

func (gcs *gopherChatterServer) Authenticate(ctx context.Context, req *gopherchatterv0.AuthenticateRequest) (*gopherchatterv0.AuthenticateResponse, error) {
	uc := user.Credentials{
		Username: req.GetUsername(),
		Password: req.GetPassword(),
	}
	ua, err := user.Authenticate(ctx, gcs.db, uc)
	if err != nil {
		return nil, err
	}
	signingKey := []byte("gopherchatter super secret")
	expiresAt := time.Now().Add(12 * time.Hour).Unix()
	claims := &jwt.StandardClaims{
		Subject:   ua.ID.Hex(),
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: expiresAt,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	log.Println(token)
	ss, err := token.SignedString(signingKey)
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "signing token",
		)
	}
	return &gopherchatterv0.AuthenticateResponse{
		Token:     ss,
		ExpiresAt: expiresAt,
	}, nil
}

// ========================================================================================
// User

func (gcs *gopherChatterServer) CreateUser(ctx context.Context, req *gopherchatterv0.CreateUserRequest) (*gopherchatterv0.CreateUserResponse, error) {
	unu := user.NewUser{
		Username:        req.GetUsername(),
		Password:        req.GetPassword(),
		PasswordConfirm: req.GetPasswordConfirm(),
	}
	if err := user.CheckFormat(ctx, gcs.db, unu); err != nil {
		return nil, err
	}
	if user.NameExists(ctx, gcs.db, req.GetUsername()) {
		return nil, status.Errorf(
			codes.AlreadyExists, "username already exists",
		)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.GetPassword()), bcrypt.DefaultCost)
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "hashing password",
		)
	}
	uu := user.User{
		Username:     req.GetUsername(),
		PasswordHash: string(hash),
	}
	uc, err := user.Create(ctx, gcs.db, uu)
	if err != nil {
		return nil, err
	}
	return &gopherchatterv0.CreateUserResponse{
		UserId:       uc.ID.Hex(),
		Username:     uc.Username,
		PasswordHash: uc.PasswordHash,
	}, nil
}

func (gcs *gopherChatterServer) SearchUsername(ctx context.Context, req *gopherchatterv0.SearchUsernameRequest) (*gopherchatterv0.SearchUsernameResponse, error) {
	authUserID, err := primitive.ObjectIDFromHex(grpc_ctxtags.Extract(ctx).Values()["auth.sub"].(string))
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	if !user.IDExists(ctx, gcs.db, authUserID) {
		return nil, status.Errorf(
			codes.NotFound, "user id in token does not exist",
		)
	}
	u, err := user.GetUsername(ctx, gcs.db, req.GetUsername())
	if err != nil {
		return nil, err
	}
	return &gopherchatterv0.SearchUsernameResponse{
		UserId:   u.ID.Hex(),
		Username: u.Username,
	}, nil
}

// ========================================================================================
// Group
func (gcs *gopherChatterServer) CreateGroupChat(ctx context.Context, req *gopherchatterv0.CreateGroupChatRequest) (*gopherchatterv0.CreateGroupChatResponse, error) {
	authUserID, err := primitive.ObjectIDFromHex(grpc_ctxtags.Extract(ctx).Values()["auth.sub"].(string))
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	if !user.IDExists(ctx, gcs.db, authUserID) {
		return nil, status.Errorf(
			codes.NotFound, "user id in token does not exist",
		)
	}
	gc := group.Chat{
		Name:  req.GetChatName(),
		Admin: authUserID,
		Members: []primitive.ObjectID{
			authUserID,
		},
	}
	gcc, err := group.CreateChat(ctx, gcs.db, gc)
	if err != nil {
		return nil, err
	}
	var cm []string
	for _, e := range gcc.Members {
		cm = append(cm, e.Hex())
	}
	return &gopherchatterv0.CreateGroupChatResponse{
		ChatId:      gcc.ID.Hex(),
		ChatName:    gcc.Name,
		ChatAdmin:   gcc.Admin.Hex(),
		ChatMembers: cm,
	}, nil
}

func (gcs *gopherChatterServer) AddContactToGroupChat(ctx context.Context, req *gopherchatterv0.AddContactToGroupChatRequest) (*gopherchatterv0.AddContactToGroupChatResponse, error) {
	authUserID, err := primitive.ObjectIDFromHex(grpc_ctxtags.Extract(ctx).Values()["auth.sub"].(string))
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	if !user.IDExists(ctx, gcs.db, authUserID) {
		return nil, status.Errorf(
			codes.NotFound, "user id in token does not exist",
		)
	}
	userID, err := primitive.ObjectIDFromHex(req.GetUserId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	if !user.IDExists(ctx, gcs.db, userID) {
		return nil, status.Errorf(
			codes.NotFound, "user id does not exist",
		)
	}
	c := contact.Contact{
		Owner: authUserID,
		User:  userID,
	}
	if !contact.Exists(ctx, gcs.db, c) {
		return nil, status.Errorf(
			codes.AlreadyExists, "user id is not a contact",
		)
	}
	chatID, err := primitive.ObjectIDFromHex(req.GetChatId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	chat, err := group.GetChat(ctx, gcs.db, chatID)
	if err != nil {
		return nil, err
	}
	if authUserID != chat.Admin {
		return nil, status.Errorf(
			codes.PermissionDenied, "not authorized to add contact",
		)
	}
	if group.ChatHasMember(chat, userID) {
		return nil, status.Errorf(
			codes.AlreadyExists, "contact already in chat",
		)
	}
	updatedChat, err := group.AddMemberToChat(ctx, gcs.db, chatID, userID)
	if err != nil {
		return nil, err
	}
	var cm []string
	for _, e := range updatedChat.Members {
		cm = append(cm, e.Hex())
	}
	cm = append(cm, userID.Hex())
	return &gopherchatterv0.AddContactToGroupChatResponse{
		ChatId:      updatedChat.ID.Hex(),
		ChatName:    updatedChat.Name,
		ChatAdmin:   updatedChat.Admin.Hex(),
		ChatMembers: cm,
	}, nil
}

func (gcs *gopherChatterServer) RemoveMemberFromGroupChat(ctx context.Context, req *gopherchatterv0.RemoveMemberFromGroupChatRequest) (*gopherchatterv0.RemoveMemberFromGroupChatResponse, error) {
	authUserID, err := primitive.ObjectIDFromHex(grpc_ctxtags.Extract(ctx).Values()["auth.sub"].(string))
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	if !user.IDExists(ctx, gcs.db, authUserID) {
		return nil, status.Errorf(
			codes.NotFound, "user id in token does not exist",
		)
	}
	userID, err := primitive.ObjectIDFromHex(req.GetUserId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	if !user.IDExists(ctx, gcs.db, userID) {
		return nil, status.Errorf(
			codes.NotFound, "user id does not exist",
		)
	}
	chatID, err := primitive.ObjectIDFromHex(req.GetChatId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	chat, err := group.GetChat(ctx, gcs.db, chatID)
	if err != nil {
		return nil, err
	}
	if authUserID != chat.Admin {
		return nil, status.Errorf(
			codes.PermissionDenied, "not authorized to remove member",
		)
	}
	if !group.ChatHasMember(chat, userID) {
		return nil, status.Errorf(
			codes.AlreadyExists, "member not in chat",
		)
	}
	updatedChat, err := group.RemoveMemberFromChat(ctx, gcs.db, chatID, userID)
	if err != nil {
		return nil, err
	}
	var cm []string
	for _, e := range updatedChat.Members {
		if e != userID {
			cm = append(cm, e.Hex())
		}

	}
	return &gopherchatterv0.RemoveMemberFromGroupChatResponse{
		ChatId:      updatedChat.ID.Hex(),
		ChatName:    updatedChat.Name,
		ChatAdmin:   updatedChat.Admin.Hex(),
		ChatMembers: cm,
	}, nil
}

// ========================================================================================
// Individual
func (gcs *gopherChatterServer) CreateIndividualChat(ctx context.Context, req *gopherchatterv0.CreateIndividualChatRequest) (*gopherchatterv0.CreateIndividualChatResponse, error) {
	authUserID, err := primitive.ObjectIDFromHex(grpc_ctxtags.Extract(ctx).Values()["auth.sub"].(string))
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	if !user.IDExists(ctx, gcs.db, authUserID) {
		return nil, status.Errorf(
			codes.NotFound, "user id in token does not exist",
		)
	}
	userID, err := primitive.ObjectIDFromHex(req.GetUserId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	if !user.IDExists(ctx, gcs.db, userID) {
		return nil, status.Errorf(
			codes.NotFound, "user id does not exist",
		)
	}
	c := contact.Contact{
		Owner: authUserID,
		User:  userID,
	}
	if !contact.Exists(ctx, gcs.db, c) {
		return nil, status.Errorf(
			codes.AlreadyExists, "not a contact",
		)
	}
	ic := individual.Chat{
		Members: []primitive.ObjectID{
			authUserID,
			userID,
		},
	}
	if individual.ChatUsersExists(ctx, gcs.db, ic) {
		return nil, status.Errorf(
			codes.AlreadyExists, "individual chat already exists",
		)
	}
	icc, err := individual.CreateChat(ctx, gcs.db, ic)
	if err != nil {
		return nil, err
	}
	var cm []string
	for _, e := range icc.Members {
		cm = append(cm, e.Hex())
	}
	return &gopherchatterv0.CreateIndividualChatResponse{
		ChatId:      icc.ID.Hex(),
		ChatMembers: cm,
	}, nil
}

// ========================================================================================
// Contact
func (gcs *gopherChatterServer) AddContact(ctx context.Context, req *gopherchatterv0.AddContactRequest) (*gopherchatterv0.AddContactResponse, error) {
	authUserID, err := primitive.ObjectIDFromHex(grpc_ctxtags.Extract(ctx).Values()["auth.sub"].(string))
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	if !user.IDExists(ctx, gcs.db, authUserID) {
		return nil, status.Errorf(
			codes.NotFound, "user id in token does not exist",
		)
	}
	userID, err := primitive.ObjectIDFromHex(req.GetUserId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	if !user.IDExists(ctx, gcs.db, userID) {
		return nil, status.Errorf(
			codes.NotFound, "user id does not exist",
		)
	}

	c := contact.Contact{
		Owner: authUserID,
		User:  userID,
	}
	if contact.Exists(ctx, gcs.db, c) {
		return nil, status.Errorf(
			codes.AlreadyExists, "already a contact",
		)
	}
	ca, err := contact.Add(ctx, gcs.db, c)
	if err != nil {
		return nil, err
	}
	return &gopherchatterv0.AddContactResponse{
		UserId:    ca.User.Hex(),
		ContactId: ca.ID.Hex(),
	}, nil
}

type gopherChatterServer struct {
	db *mongo.Database
}

func run() error {

	// ========================================================================================
	// Configuration

	var cfg struct {
		DB struct {
			Host string `conf:"default:localhost:27017"`
			Name string `conf:"default:gopherchatter"`
		}
		GRPC struct {
			Host string `conf:"default:localhost:50051"`
		}
	}
	if err := conf.Parse(os.Args[1:], "SALES", &cfg); err != nil {
		if err == conf.ErrHelpWanted {
			usage, err := conf.Usage("SALES", &cfg)
			if err != nil {
				return errors.Wrap(err, "generating config usage")
			}
			fmt.Println(usage)
			return nil
		}
		return errors.Wrap(err, "parsing config")
	}

	// ========================================================================================
	// App Starting

	log.Println("main : Started : Application initializing")
	defer log.Println("main : Completed")

	out, err := conf.String(&cfg)
	if err != nil {
		return errors.Wrap(err, "generating config for output")
	}
	log.Printf("main : Config :\n%v\n", out)

	// ========================================================================================
	// Start Database

	log.Println("main : Started : Initializing database support")

	db, err := database.Open(database.Config{
		Host: cfg.DB.Host,
		Name: cfg.DB.Name,
	})
	if err != nil {
		return errors.Wrap(err, "connecting to db")
	}
	defer func() {
		log.Printf("main : Database Stopping : %s", cfg.DB.Host)
		db.Client().Disconnect(context.Background())
	}()

	// ========================================================================================
	// Start GRPC Service

	log.Println("main : Started : Initializing GRPC support")

	// Make a channel to listen for an interrupt or terminate signal from the OS.
	// Use a buffered channel because the signal package requires it.
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	// Make a channel to listen for errors coming from the listener. Use a
	// buffered channel so the goroutine can exit if we don't collect this error.
	serverErrors := make(chan error, 1)

	listener, err := net.Listen("tcp", cfg.GRPC.Host)
	if err != nil {
		return errors.Wrap(err, "listening on network")
	}

	grpcs := grpc.NewServer(
		grpc.UnaryInterceptor(
			grpc_middleware.ChainUnaryServer(
				middleware.AddContextTags(),
				middleware.AddLogging(),
				middleware.AddAuthentication(),
			),
		),
	)
	gcs := gopherChatterServer{
		db: db,
	}
	gopherchatterv0.RegisterGopherChatterServer(grpcs, &gcs)

	// Start the service listening for requests.
	go func() {
		log.Printf("main : GRPC service listening on %s", cfg.GRPC.Host)
		serverErrors <- grpcs.Serve(listener)
	}()

	// ========================================================================================
	// Shutdown

	// Blocking main and waiting for shutdown.
	select {
	case err := <-serverErrors:
		return errors.Wrap(err, "server error")
	case sig := <-shutdown:
		log.Printf("main : %v : Start shutdown", sig)

		grpcs.Stop()
		listener.Close()

		// Log the status of this shutdown.
		switch {
		case sig == syscall.SIGSTOP:
			return errors.New("integrity issue caused shutdown")
		case err != nil:
			return errors.Wrap(err, "could not stop server gracefully")
		}

	}
	return nil
}
func main() {
	if err := run(); err != nil {
		log.Println("error :", err)
		os.Exit(1)
	}
}
