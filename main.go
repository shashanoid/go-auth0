package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Auth0 Configuration
const (
	auth0Domain       = "" // Replace with your Auth0 domain
	auth0ClientID     = "" // Replace with your Auth0 client ID
	auth0ClientSecret = "" // Replace with your Auth0 client secret
	auth0CallbackURL  = "http://localhost:8080/callback"
	auth0Audience     = "" // Optional: Your API identifier
)

// TokenResponse represents the Auth0 token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

// Store represents our in-memory data store
type Store struct {
	mu   sync.RWMutex
	data map[string]interface{}
	auth *TokenResponse
}

// Global store instance
var store = &Store{
	data: make(map[string]interface{}),
}

// Mock access token - in real application, this would be properly secured
const mockAccessToken = "mock_tk_123456789"

func (s *Store) Set(key string, value interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = value
}

func (s *Store) Get(key string) (interface{}, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	val, ok := s.data[key]
	return val, ok
}

func (s *Store) SetAuth(token *TokenResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auth = token
}

func (s *Store) GetAuth() *TokenResponse {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.auth
}

func main() {
	// Create MCP server
	s := server.NewMCPServer(
		"Auth0 Demo 🚀",
		"1.0.0",
	)

	// Add keystore tool
	keystoreTool := mcp.NewTool("keystore_access",
		mcp.WithDescription("Access the keystore data"),
		mcp.WithString("action",
			mcp.Required(),
			mcp.Description("Action to perform: get_token, get_data, login, logout"),
		),
	)

	// Add tool handlers
	s.AddTool(keystoreTool, keystoreHandler)

	// Start HTTP server in a goroutine
	go startHTTPServer()

	// Start the stdio server
	if err := server.ServeStdio(s); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}

func startHTTPServer() {
	mux := http.NewServeMux()

	// Auth0 callback endpoint
	mux.HandleFunc("/callback", handleCallback)

	// Data retrieval endpoint
	mux.HandleFunc("/data", handleData)

	fmt.Println("Starting HTTP server on port 8080...")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		fmt.Printf("HTTP server error: %v\n", err)
	}
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get the authorization code from query parameters
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	// Exchange the authorization code for tokens
	tokenData := url.Values{}
	tokenData.Set("grant_type", "authorization_code")
	tokenData.Set("client_id", auth0ClientID)
	tokenData.Set("client_secret", auth0ClientSecret)
	tokenData.Set("code", code)
	tokenData.Set("redirect_uri", auth0CallbackURL)

	tokenURL := fmt.Sprintf("https://%s/oauth/token", auth0Domain)
	resp, err := http.Post(tokenURL, "application/x-www-form-urlencoded", strings.NewReader(tokenData.Encode()))
	if err != nil {
		http.Error(w, "Failed to exchange code for token", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read token response", http.StatusInternalServerError)
		return
	}

	var tokenResponse TokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		http.Error(w, "Failed to parse token response", http.StatusInternalServerError)
		return
	}

	// Store the tokens
	store.SetAuth(&tokenResponse)

	// Return success response
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(`
		<html>
			<body>
				<h1>Authentication Successful!</h1>
				<p>You can now close this window and return to the application.</p>
				<script>window.close()</script>
			</body>
		</html>
	`))
}

func handleData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	auth := store.GetAuth()
	if auth == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	store.mu.RLock()
	response := store.data
	store.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func keystoreHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	action, ok := request.Params.Arguments["action"].(string)
	if !ok {
		return nil, errors.New("action must be a string")
	}

	switch action {
	case "get_token":
		auth := store.GetAuth()
		if auth == nil {
			return nil, errors.New("no active session")
		}
		return mcp.NewToolResultText(fmt.Sprintf("Access Token: %s", auth.AccessToken)), nil

	case "get_data":
		store.mu.RLock()
		data := store.data
		store.mu.RUnlock()

		jsonData, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("error marshaling data: %v", err)
		}
		return mcp.NewToolResultText(string(jsonData)), nil

	case "login":
		loginURL := fmt.Sprintf("https://%s/authorize?"+
			"response_type=code&"+
			"client_id=%s&"+
			"redirect_uri=%s&"+
			"scope=openid%%20profile%%20email%%20offline_access&"+
			"audience=%s",
			auth0Domain, auth0ClientID, auth0CallbackURL, auth0Audience)
		return mcp.NewToolResultText(fmt.Sprintf("Please visit this URL to login: %s", loginURL)), nil

	case "logout":
		store.SetAuth(nil)
		return mcp.NewToolResultText("Logged out successfully"), nil

	default:
		return nil, fmt.Errorf("unknown action: %s", action)
	}
}
