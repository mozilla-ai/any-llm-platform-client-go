// Package main demonstrates basic usage of the any-llm-platform-client-go library.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	anyllmplatform "github.com/mozilla-ai/any-llm-platform-client-go"
)

func main() {
	// Get the ANY_LLM_KEY from environment variable
	anyLLMKey := os.Getenv("ANY_LLM_KEY")
	if anyLLMKey == "" {
		log.Fatal("ANY_LLM_KEY environment variable is required")
	}

	// Get the provider from command line or default to "openai"
	provider := "openai"
	if len(os.Args) > 1 {
		provider = os.Args[1]
	}

	// Create a new client with default settings
	// For custom platform URL, use:
	//   client := anyllmplatform.NewClient(anyllmplatform.WithPlatformURL("https://api.example.com/v1"))
	client := anyllmplatform.NewClient()

	// Create a context (can be cancelled or have timeout)
	ctx := context.Background()

	// Get the decrypted provider key
	fmt.Printf("Fetching %s API key...\n", provider)

	result, err := client.GetDecryptedProviderKey(ctx, anyLLMKey, provider)
	if err != nil {
		log.Fatalf("Failed to get provider key: %v", err)
	}

	// Print the results
	fmt.Println("\nSuccess!")
	fmt.Printf("API Key: %s\n", result.APIKey)
	fmt.Printf("Provider Key ID: %s\n", result.ProviderKeyID)
	fmt.Printf("Project ID: %s\n", result.ProjectID)
	fmt.Printf("Provider: %s\n", result.Provider)
	fmt.Printf("Created At: %s\n", result.CreatedAt)
	if !result.UpdatedAt.IsZero() {
		fmt.Printf("Updated At: %s\n", result.UpdatedAt)
	}
}
