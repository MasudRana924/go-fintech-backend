package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

// User represents a user in the database
type User struct {
	ID         primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	Phone      string             `json:"phone" bson:"phone"`
	Password   string             `json:"password" bson:"password"`
	FirstName  string             `json:"firstName" bson:"firstName"`
	LastName   string             `json:"lastName" bson:"lastName"`
	AvatarLogo string             `json:"avatarLogo,omitempty" bson:"avatarLogo,omitempty"`
	Amount     float64            `json:"amount" bson:"amount"`
	Balance    float64            `json:"balance" bson:"balance"`
	Point      int                `json:"point" bson:"point"`
	Role       string             `json:"role" bson:"role"`
}

// Env variables
var (
	mongoURI  string
	jwtSecret string
	database  *mongo.Database
	userColl  *mongo.Collection
)

func init() {
	// Load environment variables
	if err := godotenv.Load(".env"); err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}
	mongoURI = os.Getenv("MONGODB_CONN_STRING")
	jwtSecret = os.Getenv("JWT_SECRET")

	// Connect to MongoDB
	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatalf("MongoDB connection error: %v", err)
	}
	database = client.Database("test")
	userColl = database.Collection("users")
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Phone    string `json:"phone"`
		Password string `json:"password"`
	}

	// Decode the input JSON
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	// Check if a user with the same phone number already exists
	var existingUser User
	err := userColl.FindOne(context.TODO(), bson.M{"phone": input.Phone}).Decode(&existingUser)
	if err == nil {
		http.Error(w, "User with this phone number already exists", http.StatusConflict)
		return
	}

	// Hash the user's password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	// Create a new user with default values
	user := User{
		ID:         primitive.NewObjectID(),
		Phone:      input.Phone,
		Password:   string(hashedPassword),
		FirstName:  "",
		LastName:   "",
		AvatarLogo: "",
		Amount:     0.0,
		Balance:    0.0,
		Point:      0,
		Role:       "user",
	}

	// Save the user in the database
	result, err := userColl.InsertOne(context.TODO(), user)
	if err != nil {
		http.Error(w, "Error saving user", http.StatusInternalServerError)
		return
	}

	// Respond with the created user's ID
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "User registered successfully",
		"userId":  result.InsertedID,
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Phone    string `json:"phone"`
		Password string `json:"password"`
	}

	// Decode the input JSON
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	// Find the user by phone
	var user User
	err := userColl.FindOne(context.TODO(), bson.M{"phone": creds.Phone}).Decode(&user)
	if err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	// Compare passwords
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)); err != nil {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	// Respond with a success message
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Login successful!"))
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/register", registerHandler).Methods("POST")
	r.HandleFunc("/login", loginHandler).Methods("POST")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8088"
	}
	fmt.Printf("Server running on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}
