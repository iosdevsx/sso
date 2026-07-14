package auth

import (
	"context"
	"errors"
	"log/slog"

	ssov1 "github.com/iosdevsx/protos/gen/go/sso/v1"
	"github.com/iosdevsx/sso/internal/domain/errs"
	"github.com/iosdevsx/sso/internal/lib/sl"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type handler struct {
	ssov1.UnimplementedAuthServiceServer
	authService Auth
	logger      *slog.Logger
}

type Auth interface {
	Register(ctx context.Context, email, password string) (userID int64, err error)
}

func Register(logger *slog.Logger, grpcServer *grpc.Server, authService Auth) {
	ssov1.RegisterAuthServiceServer(grpcServer, &handler{authService: authService, logger: logger})
}

func (s *handler) Register(ctx context.Context, request *ssov1.RegisterRequest) (*ssov1.RegisterResponse, error) {
	userId, err := s.authService.Register(ctx, request.Email, request.Password)
	if err != nil {
		switch {
		case errors.Is(err, errs.ErrInvalidEmail):
			return nil, status.Error(codes.InvalidArgument, "invalid email")
		case errors.Is(err, errs.ErrPasswordTooLong):
			return nil, status.Error(codes.InvalidArgument, "password too long")
		case errors.Is(err, errs.ErrPasswordTooShort):
			return nil, status.Error(codes.InvalidArgument, "password too short")
		case errors.Is(err, errs.ErrUserExists):
			return nil, status.Error(codes.AlreadyExists, "user exists")
		default:
			s.logger.Error("internal server error", sl.Err(err))
			return nil, status.Error(codes.Internal, "internal server error")
		}
	}
	return &ssov1.RegisterResponse{
		UserId: userId,
	}, nil
}
