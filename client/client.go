package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"sync"

	gopherchatterv0 "github.com/jonericcook/gopherchatter/v0"
	"google.golang.org/grpc"
)

func main() {
	cc, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("connecting to gRPC server: %v\n", err)
	}
	defer cc.Close()

	c := gopherchatterv0.NewGopherChatterClient(cc)

	stream, err := c.Message(context.Background())
	if err != nil {
		log.Fatalf("creating stream: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(2)

	// client receive
	go func() {
		for {
			res, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				log.Fatalf("receiving message: %v", err)
				break
			}
			fmt.Printf("Response: %v\n", res)
		}
		wg.Done()

	}()

	// client send
	go func() {
		var counter int
		for {
			err := stream.Send(&gopherchatterpb.Msg{
				M: "client counter: " + string(counter),
			})
			if err != nil {
				log.Fatalf("sending message: %v", err)
				break
			}
		}
		wg.Done()
	}()

	wg.Wait()
}
