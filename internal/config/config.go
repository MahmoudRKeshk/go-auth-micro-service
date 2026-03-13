package config

import (
	"errors"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	DB_Host     string
	DB_Port     string
	DB_User     string
	DB_Password string
	DB_Name     string
	DB_URL      string
	DB_SSLMode  string
	ServerPort  string
}

func (c *Config) Load() error {
	_ = godotenv.Load()
	c.DB_Host = os.Getenv("DB_HOST")
	c.DB_Port = os.Getenv("DB_PORT")
	c.DB_User = os.Getenv("DB_USER")
	c.DB_Password = os.Getenv("DB_PASSWORD")
	c.DB_Name = os.Getenv("DB_NAME")
	c.DB_URL = os.Getenv("DB_URL")
	c.DB_SSLMode = os.Getenv("DB_SSLMODE")
	c.ServerPort = os.Getenv("SERVER_PORT")

	if err := c.validateConfig(); err != nil {
		return err
	}
	return nil
}

func (c *Config) GetBURL() string {
	return "host=" + c.DB_Host + " port=" + c.DB_Port + " user=" + c.DB_User + " password=" + c.DB_Password + " dbname=" + c.DB_Name + " sslmode=" + c.DB_SSLMode
}

func (c *Config) GetServerPort() string {
	if c.ServerPort == "" {
		return ":8080" // default port
	}
	return ":" + c.ServerPort
}

func (c *Config) validateConfig() error {
	if c.DB_Host == "" {
		return errors.New("DB_HOST is not configured in the environment variables")
	}
	if c.DB_Port == "" {
		return errors.New("DB_PORT is not configured in the environment variables")
	}
	if c.DB_User == "" {
		return errors.New("DB_USER is not configured in the environment variables")
	}
	if c.DB_Password == "" {
		return errors.New("DB_PASSWORD is not configured in the environment variables")
	}
	if c.DB_Name == "" {
		return errors.New("DB_NAME is not configured in the environment variables")
	}
	if c.DB_SSLMode == "" {
		return errors.New("DB_SSLMODE is not configured in the environment variables")
	}
	return nil
}
