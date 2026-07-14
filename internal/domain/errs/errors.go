package errs

import "errors"

var (
	ErrUserExists         = errors.New("user already exists")
	ErrInvalidEmail       = errors.New("invalid email")
	ErrPasswordTooLong    = errors.New("password too long")
	ErrPasswordTooShort   = errors.New("password too short")
	ErrInternal           = errors.New("internal server error")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound       = errors.New("user not found")
)
