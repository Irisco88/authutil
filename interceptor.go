package authutil

import (
	"context"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	commonpb "github.com/openfms/protos/gen/common/v1"
	"golang.org/x/exp/slices"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net/http"
)

type AuthServerInterface interface {
	GetAuthManager() *AuthManager
	GetRoleAccess(fullMethod string) []commonpb.UserRole
}

func UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if service, ok := info.Server.(AuthServerInterface); ok {
			perms := service.GetRoleAccess(info.FullMethod)
			authManager := service.GetAuthManager()
			if authManager == nil || len(perms) == 0 {
				return handler(ctx, req)
			}
			claims, err := authManager.ExtractContext(ctx)
			if err != nil {
				return nil, status.Error(codes.Unauthenticated, err.Error())
			}
			if len(perms) > 0 && !slices.Contains(perms, claims.Role) {
				return nil, status.Error(codes.Unauthenticated, "unauthenticated request")
			}
			newCtx := context.WithValue(ctx, ClaimKey, claims)
			return handler(newCtx, req)
		}
		return handler(ctx, req)
	}
}

func StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		var newCtx context.Context
		if authSrv, ok := srv.(AuthServerInterface); ok {
			authManager := authSrv.GetAuthManager()
			perms := authSrv.GetRoleAccess(info.FullMethod)
			if authManager != nil && len(perms) > 0 {
				claim, err := authManager.ExtractContext(stream.Context())
				if err != nil {
					return status.Error(codes.Unauthenticated, err.Error())
				}
				if !slices.Contains(perms, claim.Role) {
					return status.Error(codes.Unauthenticated, "unauthenticated request")
				}
				newCtx = context.WithValue(stream.Context(), ClaimKey, claim)
			} else {
				newCtx = stream.Context()
			}
		} else {
			newCtx = stream.Context()
		}
		wrapped := grpc_middleware.WrapServerStream(stream)
		wrapped.WrappedContext = newCtx
		return handler(srv, wrapped)
	}
}

func MuxAuthMiddleware(srv any) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
			if service, ok := srv.(AuthServerInterface); ok {
				authManager := service.GetAuthManager()
				perms := service.GetRoleAccess(req.URL.Path)
				if authManager == nil || len(perms) == 0 {
					next.ServeHTTP(resp, req)
				}
				token := req.Header.Get("token")
				if len(token) == 0 {
					http.Error(resp, "token not found", http.StatusUnauthorized)
					return
				}
				claims, err := authManager.VerifyToken(token)
				if err != nil {
					http.Error(resp, err.Error(), http.StatusUnauthorized)
					return
				}
				if !slices.Contains(perms, claims.Role) {
					http.Error(resp, "unauthenticated request", http.StatusUnauthorized)
					return
				}
				newCtx := context.WithValue(req.Context(), ClaimKey, claims)
				next.ServeHTTP(resp, req.WithContext(newCtx))
			}
			next.ServeHTTP(resp, req)
		})
	}
}
