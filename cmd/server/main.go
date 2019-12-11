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

	"github.com/jonericcook/gopherchatter/internal/group"
	"github.com/jonericcook/gopherchatter/internal/middleware"
	"github.com/jonericcook/gopherchatter/internal/platform/database"
	gopherchatterv0 "github.com/jonericcook/gopherchatter/internal/platform/protobuf/v0"
	"github.com/jonericcook/gopherchatter/internal/user"
	"github.com/pkg/errors"
	"go.mongodb.org/mongo-driver/mongo"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ========================================================================================
// Authentication

func (gcs *gopherChatterServer) Authenticate(ctx context.Context, req *gopherchatterv0.AuthenticateRequest) (*gopherchatterv0.AuthenticateResponse, error) {
	ua := user.AuthUser{
		Username: req.GetUsername(),
		Password: req.GetPassword(),
	}
	u, err := user.Authenticate(ctx, gcs.db, ua)
	if err != nil {
		return nil, err
	}
	signingKey := []byte("gopherchatter")
	expiresAt := time.Now().Add(12 * time.Hour).Unix()
	claims := &jwt.StandardClaims{
		Subject:   u.ID.Hex(),
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: expiresAt,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	log.Println(token)
	ss, err := token.SignedString(signingKey)
	if err != nil {
		return nil, status.Errorf(
			codes.Unauthenticated, "username or password is incorrect",
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
	nu := user.NewUser{
		Username:        req.GetUsername(),
		Password:        req.GetPassword(),
		PasswordConfirm: req.GetPasswordConfirm(),
	}
	cu, err := user.Create(ctx, gcs.db, nu)
	if err != nil {
		return nil, err
	}
	return &gopherchatterv0.CreateUserResponse{
		UserId:       cu.ID.Hex(),
		Username:     cu.Username,
		PasswordHash: cu.PasswordHash,
	}, nil
}

// ========================================================================================
// Group
func (gcs *gopherChatterServer) CreateGroupChat(ctx context.Context, req *gopherchatterv0.CreateGroupChatRequest) (*gopherchatterv0.CreateGroupChatResponse, error) {
	admin := grpc_ctxtags.Extract(ctx).Values()["auth.sub"].(string)
	nc := group.NewChat{
		Name:    req.GetChatName(),
		Admin:   admin,
		Members: []string{admin},
	}
	cc, err := group.CreateChat(ctx, gcs.db, nc)
	if err != nil {
		return nil, err
	}
	return &gopherchatterv0.CreateGroupChatResponse{
		ChatId:      cc.ID,
		ChatName:    cc.Name,
		ChatAdmin:   cc.Admin,
		ChatMembers: cc.Members,
	}, nil
}

// ========================================================================================
// Contact

// func (gcs *gopherChatterServer) AddContact(ctx context.Context, req *gopherchatterv0.AddContactRequest) (*empty.Empty, error) {
// 	md, ok := metadata.FromIncomingContext(ctx)
// 	if !ok {
// 		return nil, status.Errorf(
// 			codes.Internal, "internal error",
// 		)
// 	}
// 	tokenString := strings.TrimPrefix(md["authorization"][0], "Bearer ")
// 	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
// 		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
// 			return nil, status.Errorf(
// 				codes.Internal, "internal error",
// 			)
// 		}
// 		return []byte("gopherchatter"), nil
// 	})
// 	if err != nil {
// 		return nil, err
// 	}
// 	claims, ok := token.Claims.(jwt.MapClaims)
// 	if !ok && !token.Valid {
// 		return nil, status.Errorf(
// 			codes.Unauthenticated, "invalid token",
// 		)
// 	}
// 	if claims["sub"] != req.GetUserId() {
// 		return nil, status.Errorf(
// 			codes.InvalidArgument, "subject in token must match user_id",
// 		)
// 	}
// 	contactID, err := primitive.ObjectIDFromHex(req.GetContactId())
// 	if err != nil {
// 		return nil, status.Errorf(
// 			codes.Internal, "internal error",
// 		)
// 	}
// 	userID, err := primitive.ObjectIDFromHex(req.GetUserId())
// 	if err != nil {
// 		return nil, status.Errorf(
// 			codes.Internal, "internal error",
// 		)
// 	}
// 	var user bson.M
// 	if err := gcs.users.FindOne(ctx, bson.M{"_id": contactID}).Decode(&user); err != nil {
// 		return nil, status.Errorf(
// 			codes.NotFound, "user not found",
// 		)
// 	}
// 	var contact bson.M
// 	if err := gcs.contacts.FindOne(ctx, bson.M{"user_id": userID, "contact_id": contactID}).Decode(&contact); err == nil {
// 		return nil, status.Errorf(
// 			codes.NotFound, "already have as contact",
// 		)
// 	}
// 	_, err = gcs.contacts.InsertOne(ctx, bson.D{
// 		{Key: "user_id", Value: userID},
// 		{Key: "contact_id", Value: contactID},
// 	})
// 	if err != nil {
// 		return nil, status.Errorf(
// 			codes.Internal, "internal error",
// 		)
// 	}
// 	return &empty.Empty{}, nil
// }

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
