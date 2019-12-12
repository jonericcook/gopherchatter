package middleware

import (
	"context"
	"strings"

	"github.com/dgrijalva/jwt-go"
	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var authentication = func(ctx context.Context) (context.Context, error) {
	m, ok := grpc.Method(ctx)
	if !ok {
		return nil, status.Errorf(
			codes.Internal, "getting grpc method",
		)
	}
	s := strings.Split(m, "/")
	switch c := s[len(s)-1]; c {
	case "CreateUser":
		return ctx, nil
	case "Authenticate":
		return ctx, nil
	default:
		tokenString, err := grpc_auth.AuthFromMD(ctx, "bearer")
		if err != nil {
			return nil, status.Errorf(
				codes.InvalidArgument, "expected authorization header format: Bearer <token>",
			)
		}
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, status.Errorf(
					codes.InvalidArgument, "token signing method",
				)
			}
			return []byte("gopherchatter super secret"), nil
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
		grpc_ctxtags.Extract(ctx).Set("auth.sub", claims["sub"])
		return ctx, nil
	}
}

// AddAuthentication adds authentication to middleware.
func AddAuthentication() grpc.UnaryServerInterceptor {
	return grpc_auth.UnaryServerInterceptor(authentication)
}
