package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
)

type HejtoPostResponse struct {
	Embedded struct {
		Items []struct {
			Title   string `json:"title"`
			Content string `json:"content"`
			// Dodaj inne pola, jeśli są potrzebne
		} `json:"items"`
	} `json:"_embedded"`
}

func GetHejtoAuthToken() (string, error) {
	data := map[string]string{
		"client_id":     os.Getenv("HEJTO_CLIENT_ID"),
		"client_secret": os.Getenv("HEJTO_CLIENT_SECRET"),
		"grant_type":    "authorization_code",
		"redirect_uri":  "https://hejto.sztafetastat.pl",
		"code":          os.Getenv("HEJTO_CODE"),
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshalling JSON:", err)
		return "", err
	}

	// Tworzenie żądania HTTP POST
	req, err := http.NewRequest("POST", "https://auth.hejto.pl/token", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making request:", err)
		return "", err
	}
	defer resp.Body.Close()

	// Odczyt odpowiedzi
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return "", err
	}

	var response map[string]interface{}
	err = json.Unmarshal(body, &response)
	if err != nil {
		fmt.Println("Error decoding json response: ", err)
		return "", err
	}

	accessToken, ok := response["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("error getting access_token from response")
	}

	// Zwrócenie wartości access_token
	return accessToken, nil
}

func GetLastSztafetaState(accessToken string) (string, error) {
	req_url := "https://api.hejto.pl/posts?community=Sztafeta&limit=1"

	req, err := http.NewRequest("GET", req_url, nil)
	if err != nil {
		return "", fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error making request %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %v", err)
	}

	var response HejtoPostResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		fmt.Println("Error decoding json response: ", err)
		return "", err
	}

	if len(response.Embedded.Items) > 0 {
		post := response.Embedded.Items[0].Content
		re := regexp.MustCompile(`^[^\r\n]+`)
		match := re.FindString(post)
		if match == "" {
			fmt.Println("No match found.")
		} else {
			fmt.Println("First line:", match)
		}
		parts := strings.Split(match, "=")
		if len(parts) < 2 {
			fmt.Println("Invalid format: '=' not found.")
			return "", err
		}
		return parts[1], nil
	} else {
		fmt.Println("No items found.")
		return "", nil
	}

}
