package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/rs/cors"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

var upgrader = websocket.Upgrader{}
var connections = make(map[*websocket.Conn]bool)
var connMutex sync.Mutex

type User struct {
	Email    string
	Password string
}

type ChatRecord struct {
	ID          int
	Message     string
	Timestamp   time.Time
	SenderEmail string
	IPAddress   string
}

var db *sql.DB

func initDB() {
	var err error
	db, err = sql.Open("mysql", "root:root@tcp(localhost:3306)/tongxin")
	if err != nil {
		log.Fatal(err)
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	if email == "" || password == "" {
		http.Error(w, "Invalid credentials", http.StatusBadRequest)
		return
	}

	if isValidPassword(password) && isValidEmail(email) {
		_, err := db.Exec("INSERT INTO users (email, password) VALUES (?, ?)", email, password)
		if err != nil {
			log.Println("Error registering user:", err)
			http.Error(w, "Registration failed", http.StatusInternalServerError)
			return
		}
		log.Printf("Registered user: %s\n", email)
		fmt.Fprintf(w, "Registered successfully")
	} else {
		http.Error(w, "Invalid credentials", http.StatusBadRequest)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	email := vars["email"]
	password := vars["password"]

	var user User
	err := db.QueryRow("SELECT email, password FROM users WHERE email = ?", email).Scan(&user.Email, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if user.Password == password {
		log.Printf("Logged in user: %s\n", email)
		fmt.Fprintf(w, "Logged in successfully")
	} else {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
	}
}

func adminLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		log.Println("Method Not Allowed")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	log.Printf("Admin login attempt: username=%s, password=%s\n", username, password)

	if username == "admin" && password == "admin" {
		log.Printf("Admin logged in: %s\n", username)
		fmt.Fprintf(w, "Admin logged in successfully")
	} else {
		log.Println("Invalid admin credentials")
		http.Error(w, "Invalid admin credentials", http.StatusUnauthorized)
	}
}

func getIPAddress(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		ips := strings.Split(forwarded, ",")
		if len(ips[0]) != 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return strings.TrimSpace(realIP)
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return ip
}

func messageHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Error upgrading connection:", err)
		return
	}
	defer func() {
		conn.Close()
		log.Println("Connection closed.")
	}()

	remoteIP := getIPAddress(r)

	connMutex.Lock()
	connections[conn] = true
	connMutex.Unlock()

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Println("Error reading message:", err)
			connMutex.Lock()
			delete(connections, conn)
			connMutex.Unlock()
			break
		}

		var msg struct {
			Email   string `json:"email"`
			Message string `json:"message"`
		}

		if err := json.Unmarshal(message, &msg); err != nil {
			log.Println("Error unmarshalling message:", err)
			continue
		}

		log.Printf("Received message from %s: %s\n", msg.Email, msg.Message)
		log.Printf("Received message: %+v\n", msg)

		result, err := db.Exec("INSERT INTO chat_records (message, sender_email, ip_address) VALUES (?, ?, ?)", msg.Message, msg.Email, remoteIP)
		if err != nil {
			log.Println("Error inserting message:", err)
		} else {
			lastInsertID, _ := result.LastInsertId()
			rowsAffected, _ := result.RowsAffected()
			log.Printf("Message inserted with ID: %d, Rows affected: %d\n", lastInsertID, rowsAffected)
		}

		for conn := range connections {
			if err := conn.WriteJSON(msg); err != nil {
				log.Println("Error writing message:", err)
				continue
			}
		}
	}
}

func adminChatRecordsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		log.Println("Received request for chat records")
		rows, err := db.Query("SELECT id, message, timestamp, sender_email, ip_address FROM chat_records ORDER BY timestamp DESC")
		if err != nil {
			log.Println("Database error:", err)
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var records []ChatRecord
		for rows.Next() {
			var record ChatRecord
			var timestampStr string
			err := rows.Scan(&record.ID, &record.Message, &timestampStr, &record.SenderEmail, &record.IPAddress)
			if err != nil {
				log.Println("Database error:", err)
				http.Error(w, "Database error", http.StatusInternalServerError)
				return
			}

			record.Timestamp, err = time.Parse("2006-01-02 15:04:05", timestampStr)
			if err != nil {
				log.Println("Error parsing timestamp:", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			records = append(records, record)
		}

		jsonData, err := json.Marshal(records)
		if err != nil {
			log.Println("Error marshalling records:", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		log.Println("Returning chat records:", string(jsonData))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(records)
	}
}

func adminDeleteRecordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	vars := mux.Vars(r)
	recordID := vars["id"]

	result, err := db.Exec("DELETE FROM chat_records WHERE id = ?", recordID)
	if err != nil {
		log.Println("Error deleting record:", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Record not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func adminFilterRecordsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	vars := mux.Vars(r)
	senderEmail := vars["email"]

	rows, err := db.Query("SELECT id, message, timestamp, sender_email, ip_address FROM chat_records WHERE sender_email = ? ORDER BY timestamp DESC", senderEmail)
	if err != nil {
		log.Println("Database error:", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var records []ChatRecord
	for rows.Next() {
		var record ChatRecord
		var timestampStr string
		err := rows.Scan(&record.ID, &record.Message, &timestampStr, &record.SenderEmail, &record.IPAddress)
		if err != nil {
			log.Println("Database error:", err)
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}

		record.Timestamp, err = time.Parse("2006-01-02 15:04:05", timestampStr)
		if err != nil {
			log.Println("Error parsing timestamp:", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		records = append(records, record)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(records)
}

func adminFilterRecordsByMessageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	vars := mux.Vars(r)
	message := vars["message"]

	rows, err := db.Query("SELECT id, message, timestamp, sender_email, ip_address FROM chat_records WHERE message LIKE ? ORDER BY timestamp DESC", "%"+message+"%")
	if err != nil {
		log.Println("Database error:", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var records []ChatRecord
	for rows.Next() {
		var record ChatRecord
		var timestampStr string
		err := rows.Scan(&record.ID, &record.Message, &timestampStr, &record.SenderEmail, &record.IPAddress)
		if err != nil {
			log.Println("Database error:", err)
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}

		record.Timestamp, err = time.Parse("2006-01-02 15:04:05", timestampStr)
		if err != nil {
			log.Println("Error parsing timestamp:", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		records = append(records, record)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(records)
}

func adminFilterRecordsByTimeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	vars := mux.Vars(r)
	startTime := vars["startTime"]
	endTime := vars["endTime"]

	rows, err := db.Query("SELECT id, message, timestamp, sender_email, ip_address FROM chat_records WHERE timestamp BETWEEN ? AND ? ORDER BY timestamp DESC", startTime, endTime)
	if err != nil {
		log.Println("Database error:", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var records []ChatRecord
	for rows.Next() {
		var record ChatRecord
		var timestampStr string
		err := rows.Scan(&record.ID, &record.Message, &timestampStr, &record.SenderEmail, &record.IPAddress)
		if err != nil {
			log.Println("Database error:", err)
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}

		record.Timestamp, err = time.Parse("2006-01-02 15:04:05", timestampStr)
		if err != nil {
			log.Println("Error parsing timestamp:", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		records = append(records, record)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(records)
}

func isValidEmail(email string) bool {
	return len(email) > 0
}

func isValidPassword(password string) bool {
	return len(password) > 0
}

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not Found", http.StatusNotFound)
	log.Printf("404 Not Found: %s\n", r.URL.Path)
}

func staticFileHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "index.html")
}

func main() {
	initDB()

	r := mux.NewRouter()

	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Accept", "Content-Type", "Content-Length", "Accept-Encoding", "X-CSRF-Token", "Authorization"},
	})

	r.HandleFunc("/register", registerHandler).Methods("POST")
	r.HandleFunc("/login/{email}/{password}", loginHandler).Methods("POST")
	r.HandleFunc("/admin/login", adminLoginHandler).Methods("POST")
	r.HandleFunc("/message", messageHandler)
	r.HandleFunc("/admin/chat_records", adminChatRecordsHandler).Methods("GET")
	r.HandleFunc("/admin/delete_record/{id}", adminDeleteRecordHandler).Methods("DELETE")
	r.HandleFunc("/admin/filter_records/{email}", adminFilterRecordsHandler).Methods("GET")
	r.HandleFunc("/admin/filter_records_by_message/{message}", adminFilterRecordsByMessageHandler).Methods("GET")
	r.HandleFunc("/admin/filter_records_by_time/{startTime}/{endTime}", adminFilterRecordsByTimeHandler).Methods("GET")

	r.NotFoundHandler = http.HandlerFunc(notFoundHandler)

	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./")))

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "index.html")
	})

	handler := c.Handler(r)

	log.Println("Starting server on :8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}
