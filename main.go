package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/rs/cors"

	"goAPI/auth" // Update this to your module name
)

type Config struct {
	DatabaseURL string
	JWTSecret   string
	Port        string
}

func loadConfig() *Config {
	// Load .env file
	godotenv.Load()

	return &Config{
		DatabaseURL: getEnv("DATABASE_URL", "postgres://user:password@localhost/goAPI_clone?sslmode=disable"),
		JWTSecret:   getEnv("JWT_SECRET", "your-super-secret-jwt-key-change-this-in-production"),
		Port:        getEnv("PORT", "8080"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func connectDB(databaseURL string) (*sql.DB, error) {
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, err
	}

	// Configure connection pool
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, err
	}

	return db, nil
}

func setupRoutes(authHandler *auth.Handler) http.Handler {
	r := mux.NewRouter()

	// API versioning
	api := r.PathPrefix("/api/v1").Subrouter()

	// Auth routes
	authRoutes := api.PathPrefix("/auth").Subrouter()
	authRoutes.HandleFunc("/register", authHandler.Register).Methods("POST")
	authRoutes.HandleFunc("/login", authHandler.Login).Methods("POST")
	authRoutes.HandleFunc("/refresh", authHandler.RefreshToken).Methods("POST")
	authRoutes.HandleFunc("/logout", authHandler.Logout).Methods("POST")

	// Health check
	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy"}`))
	}).Methods("GET")

	// Setup CORS
	c := cors.New(cors.Options{
		AllowedOrigins: []string{
			"http://localhost:3000", // React dev server
			"http://localhost:5173", // Vite dev server
		},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{
			"Accept",
			"Authorization",
			"Content-Type",
			"X-CSRF-Token",
		},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	})

	return c.Handler(r)
}

func main() {
	// Load configuration
	config := loadConfig()

	// Connect to database
	db, err := connectDB(config.DatabaseURL)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	log.Println("Connected to database successfully")

	// Initialize services
	authRepo := auth.NewRepository(db)
	jwtService := auth.NewJWTService(config.JWTSecret)
	authService := auth.NewService(authRepo, jwtService)
	authHandler := auth.NewHandler(authService)

	// Setup routes
	handler := setupRoutes(authHandler)

	// Start server
	log.Printf("Server starting on port %s", config.Port)
	log.Fatal(http.ListenAndServe(":"+config.Port, handler))
}
