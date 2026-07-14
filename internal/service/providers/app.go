package providers

import (
	"context"

	"github.com/iosdevsx/sso/internal/domain/models"
)

type provider struct {
}

func New() *provider {
	return &provider{}
}

func (p *provider) App(ctx context.Context, appID int) (models.App, error) {
	return models.App{ID: 1}, nil
}
