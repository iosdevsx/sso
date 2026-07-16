package config

import (
	"log"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

// Config represents the application configuration
type Config struct {
	Env      string       `yaml:"env"`
	GRPC     GRPCConfig   `yaml:"grpc_server"`
	DBServer DBServer     `yaml:"db_server"`
	Auth     AuthConfig   `yaml:"auth"`
	Cleaner  TokenCleaner `yaml:"token_cleaner"`
}

type GRPCConfig struct {
	Port        int           `yaml:"port" env:"GRPC_PORT"`
	Timeout     time.Duration `yaml:"timeout" env:"GRPC_TIMEOUT"`
	IdleTimeout time.Duration `yaml:"idle_timeout" env:"GRPC_IDLE_TIMEOUT"`
}

// DBServer represents database server configuration
type DBServer struct {
	Host         string `yaml:"host"`
	Port         string `yaml:"port"`
	User         string `yaml:"user" env:"SSO_POSTGRES_USER"`
	Password     string `yaml:"password" env:"SSO_POSTGRES_PASSWORD"`
	DatabaseName string `yaml:"database_name" env:"SSO_POSTGRES_DB"`
	SSLMode      string `yaml:"sslmode"`
}

type AuthConfig struct {
	TokenTTL        time.Duration `yaml:"token_ttl"`
	RefreshTokenTTL time.Duration `yaml:"refresh_token_ttl"`
	TokenSecret     string        `env:"SSO_TOKEN_SECRET"`
	MaxAttempts     int           `yaml:"max_login_attempts"`
	LockoutDuration time.Duration `yaml:"lockout_duration"`
}

type TokenCleaner struct {
	Interval  time.Duration `yaml:"interval"`
	Retention time.Duration `yaml:"retention"`
}

func MustLoad() *Config {
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		log.Fatal("CONFIG_PATH environment variable is not set")
	}

	if _, err := os.Stat(configPath); err != nil {
		log.Fatalf("error opening config file: %s", err)
	}

	var cfg Config

	err := cleanenv.ReadConfig(configPath, &cfg)
	if err != nil {
		log.Fatalf("error reading config file: %s", err)
	}

	return &cfg
}

func (cfg DBServer) DatabaseURL() string {
	dbURL := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(cfg.User, cfg.Password),
		Host:   net.JoinHostPort(cfg.Host, cfg.Port),
		Path:   "/" + cfg.DatabaseName,
		RawQuery: url.Values{
			"sslmode": {cfg.SSLMode},
		}.Encode(),
	}
	return dbURL.String()
}
