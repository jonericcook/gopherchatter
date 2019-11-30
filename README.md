# gopherchatter

docker pull mongo

docker run -d -p 27017-27019:27017-27019 --name mongodb mongo

docker start mongodb

docker stop mongodb

go version go1.13.4 darwin/amd64

protoc v0/gopherchatter.proto --go_out=plugins=grpc:.