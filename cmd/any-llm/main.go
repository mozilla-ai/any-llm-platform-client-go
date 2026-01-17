package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	anyllmplatform "github.com/mozilla-ai/any-llm-platform-client-go"
)

func main() {
	var (
		platformURL string
		anyLLMKey   string
		verbose     bool
	)

	flag.StringVar(&platformURL, "platform-url", "", "ANY LLM platform base URL (overrides default)")
	flag.StringVar(&anyLLMKey, "key", "", "ANY_LLM_KEY string (skips prompt)")
	flag.BoolVar(&verbose, "v", false, "Enable verbose output")
	flag.Parse()

	// Get provider from positional argument
	provider := flag.Arg(0)

	// Check environment variables
	if platformURL == "" {
		platformURL = os.Getenv("ANY_LLM_PLATFORM_URL")
	}
	if anyLLMKey == "" {
		anyLLMKey = os.Getenv("ANY_LLM_KEY")
	}

	// Create client with options
	var opts []anyllmplatform.Option
	if platformURL != "" {
		opts = append(opts, anyllmplatform.WithPlatformURL(platformURL))
	}
	client := anyllmplatform.NewClient(opts...)

	// Prompt for provider if not provided
	if provider == "" {
		provider = prompt("Enter Provider name (e.g., openai, anthropic): ")
	}

	// Get ANY_LLM_KEY
	anyLLMKey = getAnyLLMKey(anyLLMKey)

	// Run decryption
	if err := runDecryption(client, provider, anyLLMKey, verbose); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func prompt(message string) string {
	fmt.Print(message)
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func getAnyLLMKey(cliKey string) string {
	if cliKey != "" {
		return cliKey
	}

	envKey := os.Getenv("ANY_LLM_KEY")
	if envKey != "" {
		fmt.Println("Using ANY_LLM_KEY from environment variable")
		return envKey
	}

	return prompt("Paste ANY_LLM_KEY (ANY.v1.<kid>.<fingerprint>-<base64_key>): ")
}

func runDecryption(client *anyllmplatform.Client, provider, anyLLMKey string, verbose bool) error {
	ctx := context.Background()

	if verbose {
		fmt.Printf("Using platform URL: %s\n", client.PlatformURL)
		fmt.Printf("Provider: %s\n", provider)
	}

	result, err := client.GetDecryptedProviderKey(ctx, anyLLMKey, provider)
	if err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("SUCCESS!")
	fmt.Println("Decrypted API Key:")
	fmt.Printf("   %s\n", result.APIKey)

	if verbose {
		fmt.Printf("\nProvider Key ID: %s\n", result.ProviderKeyID)
		fmt.Printf("Project ID: %s\n", result.ProjectID)
		fmt.Printf("Provider: %s\n", result.Provider)
		fmt.Printf("Created At: %s\n", result.CreatedAt)
		if !result.UpdatedAt.IsZero() {
			fmt.Printf("Updated At: %s\n", result.UpdatedAt)
		}
	}

	return nil
}
