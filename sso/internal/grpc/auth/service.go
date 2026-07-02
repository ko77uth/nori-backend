package auth

import (
	"context"
	"errors"
	"nori/internal/services/auth"

	"github.com/go-playground/validator/v10"
	ssov1 "github.com/ko77uth/nori-backend/contracts/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Auth interface {
	Login(
		ctx context.Context,
		email string,
		password string,
		appID int,
	) (token string, err error)
	RegisterNewUser(
		ctx context.Context,
		email string,
		password string,
		name string,
		username string,
	) (userID int64, err error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
}

type serverAPI struct {
	ssov1.UnimplementedAuthServer
	auth     Auth
	validate *validator.Validate
}

func Register(gRPC *grpc.Server, auth Auth) {
	validate := validator.New()
	ssov1.RegisterAuthServer(gRPC, &serverAPI{validate: validate, auth: auth})
}

func (s *serverAPI) Login(
	ctx context.Context,
	req *ssov1.LoginRequest,
) (*ssov1.LoginResponse, error) {

	type loginRequest struct {
		Email    string `validate:"required,email"`
		Password string `validate:"required,min=8"`
	}

	err := s.validate.Struct(loginRequest{
		Email:    req.GetEmail(),
		Password: req.GetPassword(),
	})
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	token, err1 := s.auth.Login(ctx, req.GetEmail(), req.GetPassword())

	if err1 != nil {
		// TODO: ...
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &ssov1.LoginResponse{
		Token: token,
	}, nil
}

func (s *serverAPI) Register(
	ctx context.Context,
	req *ssov1.RegisterRequest,
) (*ssov1.RegisterResponse, error) {
	type registerRequest struct {
		Email    string `validate:"required,email"`
		Password string `validate:"required,min=8"`
		Name     string `validate:"required,min=2,max=50"`
		Username string `validate:"required,min=3,max=30"`
	}

	err := s.validate.Struct(registerRequest{
		Email:    req.GetEmail(),
		Password: req.GetPassword(),
		Name:     req.Name,
		Username: req.Username,
	})
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	userID, err := s.auth.RegisterNewUser(
		ctx,
		req.GetEmail(),
		req.GetPassword(),
		req.Name,
		req.Username,
	)
	if err != nil {
		if errors.Is(err, auth.ErrUserExists) {
			return nil, status.Error(codes.AlreadyExists, "user with this email or username already exists")
		}
		return nil, status.Error(codes.Internal, "failed to register user")
	}

	return &ssov1.RegisterResponse{
		UserId: userID,
	}, nil
}

func (s *serverAPI) IsAdmin(ctx context.Context, req *ssov1.IsAdminRequest) (*ssov1.IsAdminResponse, error) {
	type isAdminRequest struct {
		UserID int64 `validate:"required,gt=0"`
	}

	if err := s.validate.Struct(isAdminRequest{
		UserID: req.GetUserId(),
	}); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	isAdmin, err := s.auth.IsAdmin(ctx, req.GetUserId())
	if err != nil {
		// TODO: ...
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.IsAdminResponse{
		IsAdmin: isAdmin,
	}, nil
}
