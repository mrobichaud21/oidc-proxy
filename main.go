package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv"
)

// Your OIDC provider details (replace with your actual provider info)
var OIDC_PROVIDER_URL,
	OIDC_API_URL,
	CLIENT_ID,
	CLIENT_SECRET,
	REDIRECT_URL,
	APPLICATION_SERVER_HOST,
	APPLICATION_WEB_SERVER_PORT,
	APPLICATION_SERVER_SCHEME,
	PROXY_SERVER_PORT,
	COOKIE_NAME string

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		fmt.Println(key, value)
		return value
	}
	return fallback
}

func main() {

	err := godotenv.Load()
	if err != nil {
		log.Printf("No .env file: %v", err)
	}
	OIDC_PROVIDER_URL = getEnv("OIDC_PROVIDER_URL", "https://login.obiwalker.com")
	OIDC_API_URL = getEnv("OIDC_API_URL", "https://oidc.obiwalker.com/api/v1/token")
	CLIENT_ID = getEnv("OIDC_CLIENT_ID", "00000000-0000-0000-0000-000000000001")
	CLIENT_SECRET = getEnv("OIDC_CLIENT_SECRET", "00000000-0000-0000-0000-000000000002")
	REDIRECT_URL = getEnv("OIDC_REDIRECT_URL", "http://localhost:8080/callback")
	APPLICATION_SERVER_HOST = getEnv("APPLICATION_SERVER_HOST", "localhost")
	APPLICATION_WEB_SERVER_PORT = getEnv("APPLICATION_WEB_SERVER_PORT", "8080")
	APPLICATION_SERVER_SCHEME = getEnv("APPLICATION_SERVER_SCHEME", "http")
	PROXY_SERVER_PORT = getEnv("PROXY_SERVER_PORT", "8080")
	COOKIE_NAME = getEnv("COOKIE_NAME", "jwt")

	// Start the HTTP server to handle callback
	u, err := url.Parse(fmt.Sprintf("%s://%s:%s", APPLICATION_SERVER_SCHEME, APPLICATION_SERVER_HOST, APPLICATION_WEB_SERVER_PORT))
	//u, err := url.Parse("http://localhost:1313")
	if err != nil {
		log.Fatalf("Failed to parse proxy URL: %v", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(u)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tokenString := extractJWT(w, r)
		if tokenString == "" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		token, err := jwt.Parse(tokenString, keyFunc)
		if err != nil || !token.Valid {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		_, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenString))
		proxy.ServeHTTP(w, r)

	})
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/callback", callbackHandler)
	fmt.Printf("Listening on http://localhost:%s", PROXY_SERVER_PORT)
	log.Fatal(http.ListenAndServe(":"+PROXY_SERVER_PORT, nil))
}

// loginHandler will redirect to the OIDC provider's authorization endpoint
func loginHandler(w http.ResponseWriter, r *http.Request) {
	url := fmt.Sprintf("%s/oidc/authenticate?client_id=%s&response_type=code&redirect_uri=%s&scope=openid+profile+email&state=xyz&nonce=123", OIDC_PROVIDER_URL, CLIENT_ID, url.QueryEscape(REDIRECT_URL))
	http.Redirect(w, r, url, http.StatusFound)
}

// callbackHandler will handle the OIDC callback and exchange the code for a token
func callbackHandler(w http.ResponseWriter, r *http.Request) {
	// Get the authorization code from the URL
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Code is missing", http.StatusBadRequest)
		return
	}

	// Prepare the token request payload
	data := map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  REDIRECT_URL,
		"client_id":     CLIENT_ID,
		"client_secret": CLIENT_SECRET,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to marshal JSON: %v", err), http.StatusInternalServerError)
		return
	}

	req, err := http.NewRequest("POST", OIDC_API_URL, bytes.NewBuffer(jsonData))
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create request: %v", err), http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to make request: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Check if the request was successful
	if resp.StatusCode != http.StatusOK {
		http.Error(w, fmt.Sprintf("Failed to get token: %v", resp.Status), http.StatusInternalServerError)
		return
	}

	// Parse the response body
	var tokenResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse token response: %v", err), http.StatusInternalServerError)
		return
	}

	// Extract the ID token from the response
	idToken, ok := tokenResponse["token"].(string)
	if !ok {
		http.Error(w, "ID token not found in response", http.StatusInternalServerError)
		return
	}
	log.Println("ID Token:", idToken)

	// Set the token in a cookie
	http.SetCookie(w, &http.Cookie{
		Name:  "jwt",
		Value: idToken,

		// Secure: true, // Enable this for HTTPS
		// HttpOnly: true,
		// SameSite: http.SameSiteStrictMode,
	})

	http.Redirect(w, r, "/", http.StatusFound)
}

func extractJWT(w http.ResponseWriter, r *http.Request) string {

	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}

	cookie, err := r.Cookie("jwt")
	if err == nil {
		return cookie.Value
	}

	return ""
}

func keyFunc(token *jwt.Token) (interface{}, error) {
	// Verify the signing method is HMAC
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	// Return the secret signing key
	return []byte(CLIENT_SECRET), nil
}
