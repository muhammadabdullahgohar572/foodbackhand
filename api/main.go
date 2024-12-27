package handler

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type claims struct {
	Username    string `json:"username"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	Location    string `json:"location"`
	PhoneNumber string `json:"Phone_Number"`
	jwt.StandardClaims
}

type user struct {
	Username    string `json:"username"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	Location    string `json:"location"`
	PhoneNumber string `json:"Phone_Number"`
}



type cards struct{
	Tittle string `json:"tittle"`
	Offer string `json:"Offer"`
	Prices string `json:"prices"`
	Image string `json:"image"`
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



func order(w http.ResponseWriter, r *http.Request) {
	var newoder cards
	if err := json.NewDecoder(r.Body).Decode(&newoder); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	collection := client.Database("test").Collection("items")
	_, err := collection.InsertOne(context.TODO(), newoder)
	if err != nil {
		http.Error(w, "Error inserting user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(&newoder)

}

func signup(w http.ResponseWriter, r *http.Request) {
	var newUser user
	if err := json.NewDecoder(r.Body).Decode(&newUser); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)

	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	newUser.Password = string(hashedPassword)

	collection := client.Database("test").Collection("user")

	_, err = collection.InsertOne(context.TODO(), newUser)

	if err != nil {
		http.Error(w, "Error inserting user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(&newUser)

}

func login(w http.ResponseWriter, r *http.Request) {
	var login user

	if err := json.NewDecoder(r.Body).Decode(&login); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	collection := client.Database("test").Collection("user")

	var new user
	err := collection.FindOne(context.TODO(), bson.M{"email": login.Email}).Decode(&new)

	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(new.Password), []byte(login.Password)); err != nil {
		http.Error(w, "incorrected password ", http.StatusNotFound)
		return
	}

	claims := &claims{

		Username:    new.Username,
		Email:       new.Email,
		Password:    new.Password,
		Location:    new.Location,
		PhoneNumber: new.PhoneNumber,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 72).Unix(),
			Issuer:    "my-app",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte("abdullah55"))

	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})

}

func helloHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"massage": "Hellow all ok han"})
}

func Handler(w http.ResponseWriter, r *http.Request) {
	router := mux.NewRouter()
	router.HandleFunc("/", helloHandler).Methods("GET")
	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/order", order).Methods("POST")

	
	corsHandler := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
		AllowedHeaders:   []string{"Content-Type"},
		AllowCredentials: true,
	}).Handler(router)

	corsHandler.ServeHTTP(w, r)
}
