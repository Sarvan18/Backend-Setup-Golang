package connectDb

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Sarvan18/Backend-Setup-Golang.git/golang-Backend-Setup/config/api"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func ConnectDb() *mongo.Client {

	connectionURL := os.Getenv("CONNECTION_URL_FOR_MONGO")

	if connectionURL == "" {
		log.Fatal("Connection URL is Empty")
	}

	mongoClient, err := mongo.NewClient(options.Client().ApplyURI(connectionURL))

	if err != nil {
		log.Fatal(err)
	}

	ctx, clean := context.WithTimeout(context.Background(), 10*time.Second)

	if err = mongoClient.Connect(ctx); err != nil {
		log.Fatal(err)
	}

	fmt.Println("DB Was Connected Successfully")
	defer clean()
	return mongoClient
}

var Client *mongo.Client = ConnectDb()

func GetCollection(client mongo.Client, collectionName string) *mongo.Collection {
	return client.Database("Backend-Setup").Collection(collectionName)
}

func StartApp() {
	if err := godotenv.Load(); err != nil {
		log.Fatal(fmt.Printf("Error Loading on ENV : %v", err))
	}

	PORT := os.Getenv("PORT")

	router := api.InitApi()

	router.Run(PORT)

	fmt.Printf("Server Was Running on PORT : %s", PORT)

}
