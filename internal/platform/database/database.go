package database

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

// Config is the required properties to use the database.
type Config struct {
	Host string
	Name string
}

// Open knows how to open a database connection baed on the configuration.
func Open(cfg Config) (*mongo.Database, error) {
	client, err := mongo.NewClient(options.Client().ApplyURI("mongodb://" + cfg.Host))
	if err != nil {
		return nil, err
	}
	mongoCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = client.Connect(mongoCtx)
	if err != nil {
		return nil, err
	}
	err = client.Ping(mongoCtx, readpref.Primary())
	if err != nil {
		return nil, err
	}
	return client.Database(cfg.Name), nil
}
