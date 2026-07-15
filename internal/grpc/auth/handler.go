package auth

import (
	"context"
	"errors"
	"log/slog"

	ssov1 "github.com/iosdevsx/protos/gen/go/sso/v1"
	"github.com/iosdevsx/sso/internal/domain/errs"
	"github.com/iosdevsx/sso/internal/domain/models"
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
	Login(ctx context.Context, email, password string) (models.Tokens, error)
	Refresh(ctx context.Context, refreshToken string) (models.Tokens, error)
	Logout(ctx context.Context, refreshToken string) error
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

func (s *handler) Login(ctx context.Context, request *ssov1.LoginRequest) (*ssov1.LoginResponse, error) {
	tokens, err := s.authService.Login(ctx, request.Email, request.Password)
	if err != nil {
		switch {
		case errors.Is(err, errs.ErrInvalidCredentials):
			return nil, status.Error(codes.Unauthenticated, "invalid credentials")
		default:
			s.logger.Error("internal server error", sl.Err(err))
			return nil, status.Error(codes.Internal, "internal server error")
		}
	}
	return &ssov1.LoginResponse{Token: tokens.AccessToken, RefreshToken: tokens.RefreshToken}, nil
}

func (s *handler) Refresh(ctx context.Context, request *ssov1.RefreshRequest) (*ssov1.RefreshResponse, error) {
	tokens, err := s.authService.Refresh(ctx, request.RefreshToken)
	if err != nil {
		switch {
		case errors.Is(err, errs.ErrInvalidRefreshToken):
			return nil, status.Error(codes.Unauthenticated, "invalid refresh token")
		default:
			s.logger.Error("internal server error", sl.Err(err))
			return nil, status.Error(codes.Internal, "internal server error")
		}

	}
	return &ssov1.RefreshResponse{Token: tokens.AccessToken, RefreshToken: tokens.RefreshToken}, nil
}

func (s *handler) Logout(ctx context.Context, request *ssov1.LogoutRequest) (*ssov1.LogoutResponse, error) {
	err := s.authService.Logout(ctx, request.RefreshToken)
	if err != nil {
		s.logger.Error("internal server error", sl.Err(err))
		return nil, status.Error(codes.Internal, "internal server error")
	}
	return &ssov1.LogoutResponse{}, nil
}
