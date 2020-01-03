# Gopher Chatter

## Technologies Used
* Golang
* gRPC
* MongoDB

## Tools Needed
* [MongoDB Compass](https://www.mongodb.com/download-center/compass)
* [BloomRPC](https://github.com/uw-labs/bloomrpc#installation)
* [Docker](https://www.docker.com/get-started)
* [Golang](https://golang.org/dl/)

## Setup Instructions
### MongoDB
* Get MongoDB docker image: `docker pull mongo`
* Start MongoDB docker container for the first time: `docker run -d -p 27017-27019:27017-27019 --name mongodb mongo`
* Stop MongoDB docker container: `docker stop mongodb`
* Start MongoDB docker container: `docker start mongodb`
* Open MongoDB Compass and connect to MongoDB.

### Server
Navigate to `cmd/server` and start the server `go run .`

### BloomRPC
Open BloomRPC and import the gopherchatter protobuf file. This is done by clicking the green plus icon in the top left and navigating to the protobuf file in `internal/platform/protobuf/v0`

## Interacting
Start off by creating a user with the `CreateUser` endpoint. Use the entered credentials to authenticate that user with the `Authenticate` endpoint. Take the returned token and put it in an object as follows:
```
{
    "authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NzcxNzUyODAsImlhdCI6MTU3NzEzMjA4MCwic3ViIjoiNWUwMTFkOGNiZTQ5NzdmYTNjYzhjNGM3In0.WmWGZNaTIi2agl2_KTu45KV7_zwQO7iM8VrFvIgXbmo"
}
```
Put this object in the `METADATA` field at the bottom of the BloomRPC UI for all endpoint calls besides `CreateUser` and `Authenticate`.