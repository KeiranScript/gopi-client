package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
)

const (
	baseURL        = "http://81.140.168.36:443"
	configDir      = ".config/gopi"
	configFileName = "config.json"
)

var (
	username, password string
	verbose            bool
)

func main() {
	// Define flags
	flag.StringVar(&username, "username", "", "Username for authentication")
	flag.StringVar(&password, "password", "", "Password for authentication")
	flag.BoolVar(&verbose, "v", false, "Enable verbose output")
	help := flag.Bool("h", false, "Show help message")

	flag.Parse()

	if *help {
		printHelp()
		return
	}

	// Load configuration
	loadConfig()

	// Check if credentials are provided and validate
	if username != "" && password != "" {
		if !verifyCredentials(username, password) {
			fmt.Println("Authentication failed. Please check your username and password.")
			return
		}
		saveConfig(username, password)
		if verbose {
			fmt.Println("Authentication successful and credentials saved.")
		}
	} else {
		// If no credentials are provided, ensure config credentials are used
		if username == "" || password == "" {
			fmt.Println("No credentials provided. Please provide them via flags or config file.")
			return
		}
	}

	// Ensure config is loaded after possible saving
	loadConfig()

	// Determine action
	args := flag.Args()
	if len(args) < 1 {
		fmt.Println("Action is required. Choose from: register, upload, download, delete, list")
		return
	}

	action := args[0]

	switch action {
	case "register":
		if len(args) != 3 {
			fmt.Println("Usage: register <username> <password>")
			return
		}
		register(args[1], args[2])
	case "upload":
		if len(args) < 2 {
			fmt.Println("Usage: upload <file> [username] [password]")
			return
		}
		filePath := args[1]
		// Use provided username and password if given; otherwise, use config values
		cmdUsername := username
		cmdPassword := password
		if len(args) == 4 {
			cmdUsername = args[2]
			cmdPassword = args[3]
		}

		upload(filePath, cmdUsername, cmdPassword)
	case "download":
		if len(args) != 2 {
			fmt.Println("Usage: download <index>")
			return
		}
		download(args[1])
	case "delete":
		if len(args) != 2 {
			fmt.Println("Usage: delete <index>")
			return
		}
		deleteFile(args[1])
	case "list":
		listFiles()
	default:
		fmt.Println("Invalid action. Choose from: register, upload, download, delete, list")
	}
}

// printHelp prints usage and help information
func printHelp() {
	fmt.Println("Usage of gopi-client:")
	flag.PrintDefaults()
	fmt.Println("\nActions:")
	fmt.Println("  register <username> <password>  - Register a new user")
	fmt.Println("  upload <file> [username] [password]  - Upload a file")
	fmt.Println("  download <index>                - Download a file by index")
	fmt.Println("  delete <index>                  - Delete a file by index")
	fmt.Println("  list                            - List all files")
}

// doRequest creates and executes an HTTP request
func doRequest(method, endpoint string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, baseURL+endpoint, body)
	if err != nil {
		return nil, err
	}

	if verbose {
		fmt.Printf("Making request to %s with method %s\n", baseURL+endpoint, method)
	}

	req.SetBasicAuth(username, password)

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{}
	return client.Do(req)
}

// listFiles retrieves and displays a list of files
func listFiles() {
	resp, err := doRequest("GET", "/list-files", nil)
	if err != nil {
		fmt.Printf("Failed to list files: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("Server Response: %s\n", body)
		return
	}

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("File list:\n%s\n", body)
}

// verifyCredentials checks if the provided credentials are valid
func verifyCredentials(user, pass string) bool {
	data := map[string]string{"username": user, "password": pass}
	jsonData, err := json.Marshal(data)
	if err != nil {
		fmt.Printf("Failed to marshal JSON: %v\n", err)
		return false
	}

	resp, err := doRequest("POST", "/check-credentials", bytes.NewReader(jsonData))
	if err != nil {
		fmt.Printf("Failed to verify credentials: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return true
	}

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("Server Response: %s\n", body)
	return false
}

// register creates a new user
func register(user, pass string) {
	data := map[string]string{"username": user, "password": pass}
	jsonData, err := json.Marshal(data)
	if err != nil {
		fmt.Printf("Failed to marshal JSON: %v\n", err)
		return
	}

	resp, err := doRequest("POST", "/register-submit", bytes.NewReader(jsonData))
	if err != nil {
		fmt.Printf("Failed to register: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("Response: %s\n", body)

	saveConfig(user, pass)
}

func upload(filePath, user, pass string) {
	// Create a new file
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("Failed to open file: %v\n", err)
		return
	}
	defer file.Close()

	// Prepare the request
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		fmt.Printf("Failed to create form file: %v\n", err)
		return
	}

	_, err = io.Copy(part, file)
	if err != nil {
		fmt.Printf("Failed to copy file: %v\n", err)
		return
	}

	// Close the writer to set the terminating boundary
	writer.Close()

	// Create the request
	req, err := http.NewRequest("POST", "http://81.140.168.36:443/upload", body)
	if err != nil {
		fmt.Printf("Failed to create request: %v\n", err)
		return
	}
	req.SetBasicAuth(user, pass)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Failed to send request: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// Handle response
	respBody, _ := io.ReadAll(resp.Body)
	fmt.Printf("Server Response: %s\n", string(respBody))
}

// download retrieves and saves a file by index
func download(index string) {
	resp, err := doRequest("GET", "/download?index="+index, nil)
	if err != nil {
		fmt.Printf("Failed to download file: %v\n", err)
		return
	}
	defer resp.Body.Close()

	fileName := "downloaded_file_" + index
	file, err := os.Create(fileName)
	if err != nil {
		fmt.Printf("Failed to create file: %v\n", err)
		return
	}
	defer file.Close()

	_, err = io.Copy(file, resp.Body)
	if err != nil {
		fmt.Printf("Failed to write file: %v\n", err)
		return
	}

	fmt.Printf("File downloaded as %s\n", fileName)
}

// deleteFile removes a file by index
func deleteFile(index string) {
	indexInt, err := strconv.Atoi(index)
	if err != nil {
		fmt.Printf("Invalid index: %v\n", err)
		return
	}

	data := map[string]int{"index": indexInt}
	jsonData, err := json.Marshal(data)
	if err != nil {
		fmt.Printf("Failed to marshal JSON: %v\n", err)
		return
	}

	resp, err := doRequest("POST", "/delete", bytes.NewReader(jsonData))
	if err != nil {
		fmt.Printf("Failed to delete file: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("Response: %s\n", body)
}

// loadConfig reads and applies configuration from file
func loadConfig() {
	homeDir, _ := os.UserHomeDir()
	configPath := filepath.Join(homeDir, configDir, configFileName)

	file, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		fmt.Printf("Failed to read config file: %v\n", err)
		return
	}

	var config map[string]string
	if err := json.Unmarshal(file, &config); err != nil {
		fmt.Printf("Failed to decode config file: %v\n", err)
		return
	}

	username = config["username"]
	password = config["password"]

	if verbose {
		fmt.Printf("Loaded credentials - Username: %s, Password: %s\n", username, password)
	}
}

// saveConfig writes configuration to file
func saveConfig(user, pass string) {
	homeDir, _ := os.UserHomeDir()
	configPath := filepath.Join(homeDir, configDir, configFileName)

	config := map[string]string{
		"username": user,
		"password": pass,
	}

	data, err := json.Marshal(config)
	if err != nil {
		fmt.Printf("Failed to marshal config data: %v\n", err)
		return
	}

	err = os.WriteFile(configPath, data, 0644)
	if err != nil {
		fmt.Printf("Failed to write config file: %v\n", err)
	}
}
