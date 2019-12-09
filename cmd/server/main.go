package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/ardanlabs/conf"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_zap "github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	grpc_opentracing "github.com/grpc-ecosystem/go-grpc-middleware/tracing/opentracing"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	"github.com/jonericcook/gopherchatter/internal/platform/database"
	gopherchatterv0 "github.com/jonericcook/gopherchatter/internal/platform/protobuf/v0"
	"github.com/jonericcook/gopherchatter/internal/user"
	"github.com/pkg/errors"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

func (gcs *gopherChatterServer) CreateUser(ctx context.Context, req *gopherchatterv0.CreateUserRequest) (*gopherchatterv0.CreateUserResponse, error) {

	nu := user.NewUser{
		Name:            req.GetName(),
		Password:        req.GetPassword(),
		PasswordConfirm: req.GetPasswordConfirm(),
	}
	cu, err := user.Create(ctx, gcs.db, nu)
	if err != nil {
		return nil, err
	}
	return &gopherchatterv0.CreateUserResponse{
		Id:           cu.ID.Hex(),
		Name:         cu.Name,
		PasswordHash: cu.PasswordHash,
	}, nil
}

type gopherChatterServer struct {
	db *mongo.Database
}

func run() error {

	// =========================================================================
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

	// =========================================================================
	// App Starting

	log.Println("main : Started : Application initializing")
	defer log.Println("main : Completed")

	out, err := conf.String(&cfg)
	if err != nil {
		return errors.Wrap(err, "generating config for output")
	}
	log.Printf("main : Config :\n%v\n", out)

	// =========================================================================
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

	// =========================================================================
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
	logger, _ := zap.NewProduction()
	defer logger.Sync()
	grpcs := grpc.NewServer(
		grpc.UnaryInterceptor(
			grpc_middleware.ChainUnaryServer(
				grpc_ctxtags.UnaryServerInterceptor(),
				grpc_opentracing.UnaryServerInterceptor(),
				grpc_prometheus.UnaryServerInterceptor,
				grpc_zap.UnaryServerInterceptor(logger),
				// grpc_auth.UnaryServerInterceptor(myAuthFunction),
				grpc_recovery.UnaryServerInterceptor(),
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

	// =========================================================================
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