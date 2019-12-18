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
	"github.com/jonericcook/gopherchatter/internal/chat"
	"github.com/jonericcook/gopherchatter/internal/contact"

	// "github.com/jonericcook/gopherchatter/internal/chat"
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
	err = contact.Add(ctx, gcs.db, c)
	if err != nil {
		return nil, err
	}
	return &gopherchatterv0.AddContactResponse{}, nil
}

func (gcs *gopherChatterServer) RemoveContact(ctx context.Context, req *gopherchatterv0.RemoveContactRequest) (*gopherchatterv0.RemoveContactResponse, error) {
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
			codes.AlreadyExists, "contact does not exist",
		)
	}
	err = contact.Remove(ctx, gcs.db, c)
	if err != nil {
		return nil, err
	}
	return &gopherchatterv0.RemoveContactResponse{}, nil
}

func (gcs *gopherChatterServer) GetContactsList(ctx context.Context, req *gopherchatterv0.GetContactsListRequest) (*gopherchatterv0.GetContactsListResponse, error) {
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
	cga, err := contact.GetAll(ctx, gcs.db, authUserID)
	if err != nil {
		return nil, err
	}
	var users []*gopherchatterv0.User
	for _, e := range cga {
		u, err := user.GetUserID(ctx, gcs.db, e.User)
		if err != nil {
			return nil, err
		}
		users = append(users, &gopherchatterv0.User{UserId: u.ID.Hex(), Username: u.Username})
	}
	return &gopherchatterv0.GetContactsListResponse{
		Users: users,
	}, nil
}

// ========================================================================================
// Chat

func (gcs *gopherChatterServer) CreateChat(ctx context.Context, req *gopherchatterv0.CreateChatRequest) (*gopherchatterv0.CreateChatResponse, error) {
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
	var admins []primitive.ObjectID
	switch req.GetChatType() {
	case chat.Type.Group.Name:
		if req.GetChatName() == "" {
			return nil, status.Errorf(
				codes.InvalidArgument, "chat name must not be blank for group chats",
			)
		}
		if len(req.GetChatMembers()) < 1 &&
			len(req.GetChatMembers()) > chat.Type.Group.MemberLimit {
			return nil, status.Errorf(
				codes.InvalidArgument, "chat members must contain at least one user and at most 999 users for group chats",
			)
		}
		admins = append(admins, authUserID)
	case chat.Type.Individual.Name:
		if req.GetChatName() != "" {
			return nil, status.Errorf(
				codes.InvalidArgument, "chat name must be blank for individual chats",
			)
		}
		if len(req.GetChatMembers()) != 1 {
			return nil, status.Errorf(
				codes.InvalidArgument, "chat members must contain one user for individual chats",
			)
		}
	default:
		return nil, status.Errorf(
			codes.InvalidArgument, "chat type must be either 'group' or 'individual'",
		)
	}
	var members []primitive.ObjectID
	for _, e := range req.GetChatMembers() {
		userID, err := primitive.ObjectIDFromHex(e)
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
				codes.AlreadyExists, "contact does not exist",
			)
		}
		members = append(members, userID)
	}
	members = append(members, authUserID)
	cc := chat.Chat{
		Name:    req.GetChatName(),
		Type:    req.GetChatType(),
		Admins:  admins,
		Members: members,
	}
	ccc, err := chat.CreateChat(ctx, gcs.db, cc)
	if err != nil {
		return nil, err
	}
	var chatAdmins []string
	for _, e := range ccc.Admins {
		chatAdmins = append(chatAdmins, e.Hex())
	}
	var chatMembers []string
	for _, e := range ccc.Members {
		chatMembers = append(chatMembers, e.Hex())
	}
	return &gopherchatterv0.CreateChatResponse{
		ChatId:      ccc.ID.Hex(),
		ChatName:    ccc.Name,
		ChatType:    ccc.Type,
		ChatAdmins:  chatAdmins,
		ChatMembers: chatMembers,
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
