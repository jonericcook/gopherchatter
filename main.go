// package main

// import (
// 	"context"
// 	"fmt"
// 	"log"
// 	"os"
// 	"time"

// 	"go.mongodb.org/mongo-driver/bson"
// 	"go.mongodb.org/mongo-driver/mongo"
// 	"go.mongodb.org/mongo-driver/mongo/options"
// )

// func main() {
// 	password, ok := os.LookupEnv("MONGODB_PASSWORD")
// 	if !ok {
// 		log.Fatalln("unable to find MONGODB_PASSWORD in the environment")
// 	}
// 	host := "gopherchatter-lzxpi.mongodb.net/test?retryWrites=true&w=majority"
// 	username := "jonericcook"
// 	mongoURI := fmt.Sprintf("mongodb+srv://%s:%s@%s", username, password, host)
// 	client, err := mongo.NewClient(options.Client().ApplyURI(mongoURI))
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
// 	defer cancel()

// 	err = client.Connect(ctx)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	defer client.Disconnect(ctx)

// 	db := client.Database("gopherchatter")
// 	users := db.Collection("users")
// 	messages := db.Collection("messages")

// 	userResult1, err := users.InsertOne(ctx, bson.D{
// 		{Key: "first_name", Value: "dfghdfgh"},
// 		{Key: "last_name", Value: "dfgh"},
// 		{Key: "email", Value: "dfgdfh"},
// 		{Key: "password", Value: "hello"},
// 	})
// 	userResult2, err := users.InsertOne(ctx, bson.D{
// 		{Key: "first_name", Value: "sdfsdf"},
// 		{Key: "last_name", Value: "asfd"},
// 		{Key: "email", Value: "fghdfgh"},
// 		{Key: "password", Value: "hi"},
// 	})
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	messageResult, err := messages.InsertOne(ctx, bson.D{
// 		{Key: "from", Value: userResult1.InsertedID},
// 		{Key: "to", Value: userResult2.InsertedID},
// 		{Key: "message", Value: "hello there my love"},
// 	})
// 	log.Println(messageResult.InsertedID)

// 	cursor, err := messages.Find(ctx, bson.M{})
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	var msgs []bson.M
// 	if err = cursor.All(ctx, &msgs); err != nil {
// 		log.Fatal(err)
// 	}
// 	log.Println(msgs)
// }

package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/jonericcook/gopherchatter/gopherchatterpb"
	"google.golang.org/grpc"
)

type server struct{}

func (*server) Message(stream gopherchatterpb.GopherChatter_MessageServer) error {
	fmt.Println("BiDi Message start")
	var wg sync.WaitGroup
	wg.Add(2)
	mCh := make(chan string)
	eCh := make(chan error)

	// server send
	go func() {
		for m := range mCh {
			time.Sleep(3 * time.Second)
			err := stream.Send(&gopherchatterpb.Msg{
				M: "server received message: " + m,
			})
			if err != nil {
				fmt.Printf("error sending: %v", err)
				eCh <- err
				break
			}
		}
		wg.Done()
		fmt.Println("wait group done in send")
	}()

	// server receive
	go func() {
		for {
			req, err := stream.Recv()
			if err == io.EOF {
				fmt.Printf("EOF received: %v\n", err)
				eCh <- err
				break
			}
			if err != nil {
				fmt.Printf("unknown error: %v\n", err)
				eCh <- err
				break
			}
			mCh <- req.GetM()
		}
		wg.Done()
		fmt.Println("wait group done in receive")
	}()
	wg.Wait()
	fmt.Println("after wait")
	return <-eCh
}

func main() {
	listener, err := net.Listen("tcp", "0.0.0.0:50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	gopherchatterpb.RegisterGopherChatterServer(s, &server{})
	fmt.Println("gRPC server started on 0.0.0.0:50051")
	if err := s.Serve(listener); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
