package middleware

import (
	grpc_zap "github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

// AddLogging adds logging to middleware.
func AddLogging() grpc.UnaryServerInterceptor {
	logger, _ := zap.NewProduction()
	defer logger.Sync()
	return grpc_zap.UnaryServerInterceptor(logger)
}
