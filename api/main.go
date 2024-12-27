package handler

import (
	
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type user struct {
	username     string `json:"username"`
	Email        string `json:"email"`
	password     string `json:"password"`
	location     string `json:"location"`
	Phone_Number string `json:"Phone_Number"`
}

var (
	mongoURI = "mongodb+srv://muhammadabdullahgohar572:ilove1382005@cluster0.ifs70.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0" // Retrieve MongoDB URI from environment variable
	client   *mongo.Client
)

func init() {
	var err error
	client, err = mongo.Connect(context.TODO(), options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatal("DB connection error:", err)
	}
	log.Println("Connected to MongoDB")
}

func signup(w http.ResponseWriter, r *http.Request) {
	var newUser user
	if err := json.NewDecoder(r.Body).Decode(&newUser); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.password), bcrypt.DefaultCost)

	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	newUser.password = string(hashedPassword)

	collection := client.Database("test").Collection("user")

	_, err = collection.InsertOne(context.TODO(), newUser)

	if err != nil {
		http.Error(w, "Error inserting user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(&newUser)

}

func helloHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"massage": "Hellow all ok han"})
}

func Handler(w http.ResponseWriter, r *http.Request) {
	router := mux.NewRouter()
	router.HandleFunc("/", helloHandler).Methods("GET")
	router.HandleFunc("/signup", signup).Methods("POST")


	corsHandler := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
		AllowedHeaders:   []string{"Content-Type"},
		AllowCredentials: true,
	}).Handler(router)

	corsHandler.ServeHTTP(w, r)
}
