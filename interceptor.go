package authutil

import (
	"context"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	commonpb "github.com/openfms/protos/gen/common/v1"
	"golang.org/x/exp/slices"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
