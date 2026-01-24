package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
	"os"
)

var jwtKey = []byte("my_secret_key_cvwo_2026")

func init() {
    // Try to get the secret from the environment variables
    secret := os.Getenv("JWT_SECRET")
    if secret != "" {
        // If found, use the secure key instead of the hardcoded one
        jwtKey = []byte(secret)
    }
}

// Structure of the token
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

var db *sql.DB // The global database connection

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./forum.db")
	if err != nil {
		panic(err)
	}

	// Create USERS table
	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT
        )
    `)
	if err != nil {
		panic(err)
	}

	// Create TOPICS table
	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS topics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            author TEXT
        )
    `)
	if err != nil {
		panic(err)
	}

	// Create POSTS table
	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            topic_id INTEGER,
            title TEXT,
            body TEXT,
            author TEXT
        )
    `)
	if err != nil {
		panic(err)
	}

	// Create COMMENTS table
	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER,
            body TEXT,
            author TEXT
        )
    `)
	if err != nil {
		panic(err)
	}

	fmt.Println("Database initialized successfully!")

}

// --- THE DATA MODEL ---

type Topic struct {
	ID     int    `json:"id"`
	Title  string `json:"title"`
	Author string `json:"author"`
}

type Post struct {
	ID      int    `json:"id"`
	TopicID int    `json:"topic_id"` // Foreign Key: links to a Topic
	Title   string `json:"title"`
	Body    string `json:"body"`
	Author  string `json:"author"`
}

type Comment struct {
	ID     int    `json:"id"`
	PostID int    `json:"post_id"` // Foreign Key: links to a Post
	Body   string `json:"body"`
	Author string `json:"author"`
	IsPinned bool   `json:"is_pinned"`
}

// --- CRUD OPERATIONS ---

// Get all Topics (GET)
func getTopics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
	w.Header().Set("Content-Type", "application/json")

	rows, err := db.Query("SELECT id, title, author FROM topics")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var topics []Topic
	for rows.Next() {
		var t Topic
		// Scan copies the columns into our struct fields
		if err := rows.Scan(&t.ID, &t.Title, &t.Author); err != nil {
			continue
		}
		topics = append(topics, t)
	}

	json.NewEncoder(w).Encode(topics)
}

// Get a specific Topic by ID (GET)
func getTopic(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
	w.Header().Set("Content-Type", "application/json")

	idStr := r.URL.Query().Get("id")

	// Query the database for this specific ID
	row := db.QueryRow("SELECT id, title, author FROM topics WHERE id = ?", idStr)

	var t Topic
	if err := row.Scan(&t.ID, &t.Title, &t.Author); err != nil {
		http.Error(w, "Topic not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(t)
}

// Create Topic (POST)
func createTopic(w http.ResponseWriter, r *http.Request) {
    // Setup CORS
	enableCors(&w)
	if r.Method == "OPTIONS" { return }

	// Extract user from cookie
	c, err := r.Cookie("token")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	claims := &Claims{}
	jwt.ParseWithClaims(c.Value, claims, func(token *jwt.Token) (interface{}, error) { return jwtKey, nil })

	var t Topic
	json.NewDecoder(r.Body).Decode(&t)

	// Insert using the CLAIM username
	res, err := db.Exec("INSERT INTO topics (title, author) VALUES (?, ?)",
		t.Title, claims.Username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

    // Obtain the new ID and return the created object
	id, _ := res.LastInsertId()
	t.ID = int(id)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(t)
}

// Update Topic (PUT) -> Rename a topic
func updateTopic(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	if r.Method == "OPTIONS" {
		return
	}

	var t Topic
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	c, err := r.Cookie("token")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	claims := &Claims{}
	jwt.ParseWithClaims(c.Value, claims, func(token *jwt.Token) (interface{}, error) { return jwtKey, nil })

	// Check ownership
	var author string

	// Query who owns the topic
	err = db.QueryRow("SELECT author FROM topics WHERE id = ?", t.ID).Scan(&author)
	if err != nil {
		http.Error(w, "Topic not found", http.StatusNotFound)
		return
	}

	// Compare User vs Topic Author
	if author != claims.Username {
		http.Error(w, "Forbidden: You do not own this topic", http.StatusForbidden)
		return
	}

	db.Exec("UPDATE topics SET title = ? WHERE id = ?", t.Title, t.ID)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(t)
}

// Delete Topic (DELETE)
func deleteTopic(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	if r.Method == "OPTIONS" {
		return
	}

	idStr := r.URL.Query().Get("id")

	c, err := r.Cookie("token")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	claims := &Claims{}
	jwt.ParseWithClaims(c.Value, claims, func(token *jwt.Token) (interface{}, error) { return jwtKey, nil })

	// Check ownership
	var author string
	// Query who owns the topic
	err = db.QueryRow("SELECT author FROM topics WHERE id = ?", idStr).Scan(&author)
	if err != nil {
		http.Error(w, "Topic not found", http.StatusNotFound)
		return
	}

	// Compare User vs Database Author
	if author != claims.Username {
		http.Error(w, "Forbidden: You do not own this topic", http.StatusForbidden)
		return
	}

	// CASCADE DELETE LOGIC:
	// 1. Delete all comments on posts belonging to this topic
	// Delete comments where post_id is in the list of posts for this topic
	db.Exec(`
        DELETE FROM comments 
        WHERE post_id IN (SELECT id FROM posts WHERE topic_id = ?)`, idStr)

	// 2. Delete all posts in this topic
	db.Exec("DELETE FROM posts WHERE topic_id = ?", idStr)

	// 3. Finally, delete the topic itself
	_, err = db.Exec("DELETE FROM topics WHERE id = ?", idStr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

// Get Posts by Topic (for the Topic View)
func getPostsByTopic(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")

	topicID := r.URL.Query().Get("topic_id")
	rows, err := db.Query("SELECT id, topic_id, title, body, author FROM posts WHERE topic_id = ?", topicID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var filteredPosts []Post
	for rows.Next() {
		var p Post
		if err := rows.Scan(&p.ID, &p.TopicID, &p.Title, &p.Body, &p.Author); err != nil {
			continue
		}
		filteredPosts = append(filteredPosts, p)
	}

	json.NewEncoder(w).Encode(filteredPosts)
}

// Get a specific Post by ID
func getPost(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
	w.Header().Set("Content-Type", "application/json")

	idStr := r.URL.Query().Get("id")

	// Use QueryRow for a single result
	row := db.QueryRow("SELECT id, topic_id, title, body, author FROM posts WHERE id = ?", idStr)

	var p Post
	err := row.Scan(&p.ID, &p.TopicID, &p.Title, &p.Body, &p.Author)

	if err == sql.ErrNoRows {
		http.Error(w, "Post not found", http.StatusNotFound) // 404
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError) // 500
		return
	}

	json.NewEncoder(w).Encode(p)
}

// Create Post (POST)
func createPost(w http.ResponseWriter, r *http.Request) {
	
	enableCors(&w)
	if r.Method == "OPTIONS" {
		return
	}

	c, err := r.Cookie("token")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	claims := &Claims{}
	jwt.ParseWithClaims(c.Value, claims, func(token *jwt.Token) (interface{}, error) { return jwtKey, nil })

	var p Post
	json.NewDecoder(r.Body).Decode(&p)

	res, err := db.Exec("INSERT INTO posts (topic_id, title, body, author) VALUES (?, ?, ?, ?)",
		p.TopicID, p.Title, p.Body, claims.Username)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	id, _ := res.LastInsertId()
	p.ID = int(id)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(p)
}

// Update Post (PUT)
func updatePost(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	if r.Method == "OPTIONS" {
		return
	}

	var p Post
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	c, err := r.Cookie("token")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	claims := &Claims{}
	jwt.ParseWithClaims(c.Value, claims, func(token *jwt.Token) (interface{}, error) { return jwtKey, nil })

	// Check ownership
	var author string
	// Query who owns the post
	err = db.QueryRow("SELECT author FROM posts WHERE id = ?", p.ID).Scan(&author)
	if err != nil {
		http.Error(w, "Post not found", http.StatusNotFound)
		return
	}

	// Compare User vs Database Author
	if author != claims.Username {
		http.Error(w, "Forbidden: You do not own this post", http.StatusForbidden)
		return
	}

	// Update SQL
	db.Exec("UPDATE posts SET title=?, body=? WHERE id=?", p.Title, p.Body, p.ID)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(p)
}

// Delete Post (DELETE)
func deletePost(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	if r.Method == "OPTIONS" {
		return
	}

	idStr := r.URL.Query().Get("id")

	c, err := r.Cookie("token")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	claims := &Claims{}
	jwt.ParseWithClaims(c.Value, claims, func(token *jwt.Token) (interface{}, error) { return jwtKey, nil })

	// Check ownership
	var author string
	// Query who owns the post
	err = db.QueryRow("SELECT author FROM posts WHERE id = ?", idStr).Scan(&author)
	if err != nil {
		http.Error(w, "Post not found", http.StatusNotFound)
		return
	}

	// Compare User vs Database Author
	if author != claims.Username {
		http.Error(w, "Forbidden: You do not own this post", http.StatusForbidden)
		return
	}

	// If matched, proceed to delete
	db.Exec("DELETE FROM posts WHERE id = ?", idStr)
	// Also delete associated comments
	db.Exec("DELETE FROM comments WHERE post_id = ?", idStr)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

// Get Comments for a specific Post (GET)
func getComments(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")

	postID := r.URL.Query().Get("post_id")

	query := `
		SELECT 
			id, 
			body, 
			author,
			is_pinned
		FROM comments
		WHERE post_id = ?
		ORDER BY is_pinned DESC, id ASC -- Pinned first, then newest
	`

	rows, err := db.Query(query, postID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var filteredComments []Comment
	for rows.Next() {
		var c Comment
		if err := rows.Scan(&c.ID, &c.Body, &c.Author, &c.IsPinned); err != nil {
			continue
		}
		filteredComments = append(filteredComments, c)
	}

	// Return empty list [] instead of null if none found
	if filteredComments == nil {
		filteredComments = []Comment{}
	}
	json.NewEncoder(w).Encode(filteredComments)
}

// Create Comment (POST)
func createComment(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	if r.Method == "OPTIONS" {
		return
	}

	// Check Cookie
	c, err := r.Cookie("token")
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Parse & Validate Token
	tokenStr := c.Value
	claims := &Claims{}
	jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	// Decode the Request Body
	var cm Comment
	json.NewDecoder(r.Body).Decode(&cm)

	// Insert into Database
	res, err := db.Exec("INSERT INTO comments (post_id, body, author) VALUES (?, ?, ?)",
		cm.PostID, cm.Body, claims.Username)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return the created object 
	id, _ := res.LastInsertId()
	cm.ID = int(id)
	cm.Author = claims.Username // Send back the real author so the UI can display it

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(cm)
}

// Update Comment (PUT)
func updateComment(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	if r.Method == "OPTIONS" {
		return
	}

	var cm Comment
	if err := json.NewDecoder(r.Body).Decode(&cm); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	c, err := r.Cookie("token")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	claims := &Claims{}
	jwt.ParseWithClaims(c.Value, claims, func(token *jwt.Token) (interface{}, error) { return jwtKey, nil })

	// Check ownership
	var author string

	// Query who owns the comment
	err = db.QueryRow("SELECT author FROM comments WHERE id = ?", cm.ID).Scan(&author)
	if err != nil {
		http.Error(w, "Comment not found", http.StatusNotFound)
		return
	}

	// Compare Cookie User vs Database Author
	if author != claims.Username {
		http.Error(w, "Forbidden: You do not own this comment", http.StatusForbidden)
		return
	}

	// Only update the body, author doesn't change
	_, err = db.Exec("UPDATE comments SET body = ? WHERE id = ?", cm.Body, cm.ID)
	if err != nil {
	    http.Error(w, err.Error(), http.StatusInternalServerError)
	    return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(cm)
}

// Delete Comment (DELETE)
func deleteComment(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	if r.Method == "OPTIONS" {
		return
	}

	idStr := r.URL.Query().Get("id")

	c, err := r.Cookie("token")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	claims := &Claims{}
	jwt.ParseWithClaims(c.Value, claims, func(token *jwt.Token) (interface{}, error) { return jwtKey, nil })

	// Check ownership
	var author string

	// Query who owns the comment
	err = db.QueryRow("SELECT author FROM comments WHERE id = ?", idStr).Scan(&author)
	if err != nil {
		http.Error(w, "Comment not found", http.StatusNotFound)
		return
	}

	// Compare Cookie User vs Database Author
	if author != claims.Username {
		http.Error(w, "Forbidden: You do not own this comment", http.StatusForbidden)
		return
	}

	_, err = db.Exec("DELETE FROM comments WHERE id = ?", idStr)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

func togglePin(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	if r.Method == "OPTIONS" {
		return
	}

	// Authenticate User

	c, err := r.Cookie("token")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	claims := &Claims{}
	jwt.ParseWithClaims(c.Value, claims, func(token *jwt.Token) (interface{}, error) { return jwtKey, nil })
	currentUser := claims.Username

	// Parse Request
    var req struct {
        CommentID int `json:"comment_id"`
    }
    json.NewDecoder(r.Body).Decode(&req)

	// Security Check: Is the currentUser the owner of the POST?
    // Look up the Post Author based on the Comment ID
    var postAuthor string
    err = db.QueryRow(`
        SELECT p.author 
        FROM posts p 
        JOIN comments c ON p.id = c.post_id 
        WHERE c.id = ?`, req.CommentID).Scan(&postAuthor)

    if err != nil {
        http.Error(w, "Comment not found", http.StatusNotFound)
        return
    }

    if currentUser != postAuthor {
        http.Error(w, "Only the post author can pin comments", http.StatusForbidden)
        return
    }

	// Toggle the Pin (True -> False, False -> True)
    _, err = db.Exec("UPDATE comments SET is_pinned = NOT is_pinned WHERE id = ?", req.CommentID)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
}

// --- AUTHENTICATION ---

func register(w http.ResponseWriter, r *http.Request) {
    enableCors(&w)
    if r.Method == "OPTIONS" { return }

    var u struct {
        Username string `json:"username"`
        Password string `json:"password"`
    }
    if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    // Hash Password
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
    if err != nil {
        http.Error(w, "Server error", http.StatusInternalServerError)
        return
    }

    // Insert User
    _, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", u.Username, string(hashedPassword))
    if err != nil {
        http.Error(w, "Username already taken", http.StatusConflict)
        return
    }

    // Auto-login upon registration

    // Create the Claims
    expirationTime := time.Now().Add(24 * time.Hour)
    claims := &Claims{
        Username: u.Username,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(expirationTime),
        },
    }

    // Sign the Token
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString(jwtKey)
    if err != nil {
        http.Error(w, "Server error creating token", http.StatusInternalServerError)
        return
    }

    // Set the Cookie
    http.SetCookie(w, &http.Cookie{
        Name:     "token",
        Value:    tokenString,
        Expires:  expirationTime,
        HttpOnly: true,
        Secure:   true, 
        Path:     "/",
        SameSite: http.SameSiteNoneMode,
    })

    // Return Success
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(map[string]string{"status": "created", "username": u.Username})
}

func login(w http.ResponseWriter, r *http.Request) {
	enableCors(&w) 
	if r.Method == "OPTIONS" {
		return
	}

	var u struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	json.NewDecoder(r.Body).Decode(&u)

	// Verify Password
	var storedHash string
	err := db.QueryRow("SELECT password FROM users WHERE username = ?", u.Username).Scan(&storedHash)
	if err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(u.Password)); err != nil {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	// Create the JWT
	expirationTime := time.Now().Add(24 * time.Hour) // Token valid for 1 day
	claims := &Claims{
		Username: u.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Set the Cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    tokenString,
		Expires:  expirationTime,
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
		SameSite: http.SameSiteNoneMode,
	})

	// Return success
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "username": u.Username})
}

func validateSession(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)

	// Get the Cookie
	c, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Parse the Token
	tokenStr := c.Value
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Send back the username
	json.NewEncoder(w).Encode(map[string]string{"username": claims.Username})
}

func logout(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)

	// Overwrite the cookie with an expired one
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   "",
		Expires: time.Now(),
		Path:    "/",
	})
	w.WriteHeader(http.StatusOK)
}

func enableCors(w *http.ResponseWriter) {
	allowedOrigin := os.Getenv("FRONTEND_URL")
    if allowedOrigin == "" {
        allowedOrigin = "http://localhost:3000" // Default for local development
    }

	(*w).Header().Set("Access-Control-Allow-Origin", allowedOrigin)
	(*w).Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	(*w).Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	(*w).Header().Set("Access-Control-Allow-Credentials", "true") // REQUIRED for cookies
}

// // NEW enableCors: Takes the Request 'r' to see where it came from
// func enableCors(w *http.ResponseWriter, r *http.Request) {
//     origin := r.Header.Get("Origin")
// 	fmt.Println("origin: ", origin)

//     // The Whitelist
//     allowedOrigins := map[string]bool{
//         "http://localhost:3000":          true,
//         "https://cvwo-forum.netlify.app": true, // <--- VERIFY THIS SPELLING IS CORRECT
//     }

//     if allowedOrigins[origin] {
//     	(*w).Header().Set("Access-Control-Allow-Origin", origin) // COULD BE RENDER ISSUE!!!!!!
// 	}
//     // } else {
//     //     // Fallback: If unknown, just let localhost in (useful for testing)
//     //     (*w).Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
//     // }

//     (*w).Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
//     (*w).Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
//     (*w).Header().Set("Access-Control-Allow-Credentials", "true")
// }

// --- MAIN SETUP ---

func main() {
	initDB()
	defer db.Close()

	// Topics
	http.HandleFunc("/topics", getTopics)
	http.HandleFunc("/topic", getTopic)            
	http.HandleFunc("/topics/create", createTopic) 
	http.HandleFunc("/topics/update", updateTopic) 
	http.HandleFunc("/topics/delete", deleteTopic) 

	// Posts
	http.HandleFunc("/posts", getPostsByTopic)
	http.HandleFunc("/post", getPost)
	http.HandleFunc("/posts/create", createPost)
	http.HandleFunc("/posts/delete", deletePost)
	http.HandleFunc("/posts/update", updatePost)

	// Comments
	http.HandleFunc("/comments", getComments)
	http.HandleFunc("/comments/create", createComment)
	http.HandleFunc("/comments/update", updateComment)
	http.HandleFunc("/comments/delete", deleteComment)
	http.HandleFunc("/comments/pin", togglePin)

    // Authentication
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/validate", validateSession)
	http.HandleFunc("/logout", logout)

	fmt.Println("Server starting on port 8080...")
	http.ListenAndServe(":8080", nil)
}
