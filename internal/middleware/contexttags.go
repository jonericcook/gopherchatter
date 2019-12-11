package middleware

import (
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	"google.golang.org/grpc"
)

// AddContextTags adds context tags to middleware.
func AddContextTags() grpc.UnaryServerInterceptor {
	return grpc_ctxtags.UnaryServerInterceptor()
}
