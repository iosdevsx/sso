package auth

import (
	"context"

	ssov1 "github.com/iosdevsx/protos/gen/go/sso/v1"
	"google.golang.org/grpc"
)

type serverAPI struct {
	ssov1.UnimplementedAuthServiceServer
	auth Auth
}

type Auth interface {
	Login(ctx context.Context, email, password string, appID int32) (token string, err error)
	Register(ctx context.Context, email, password string) (userID int64, err error)
}

func Register(gRpcServer *grpc.Server, auth Auth) {
	ssov1.RegisterAuthServiceServer(gRpcServer, &serverAPI{auth: auth})
}
