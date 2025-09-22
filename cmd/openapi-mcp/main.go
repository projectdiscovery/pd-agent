package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

func main() {
	baseURL := flag.String("url", "", "Base URL of the target API")
	openapiPath := flag.String("openapi", "", "Path to OpenAPI specification file")
	openapiURL := flag.String("openapi-url", "", "URL to OpenAPI specification")
	flag.Parse()

	if *baseURL == "" {
		log.Fatal("--target-url must be provided")
	}

	var swagger *openapi3.T
	var err error

	if *openapiPath != "" {
		swagger, err = openapi3.NewLoader().LoadFromFile(*openapiPath)
		if err != nil {
			log.Fatalf("Failed to load OpenAPI specification from file: %v", err)
		}
	} else if *openapiURL != "" {
		// Convert string URL to *url.URL
		parsedURL, err := url.Parse(*openapiURL)
		if err != nil {
			log.Fatalf("Invalid URL: %v", err)
		}
		swagger, err = openapi3.NewLoader().LoadFromURI(parsedURL)
		if err != nil {
			log.Fatalf("Failed to load OpenAPI specification from URL: %v", err)
		}
	} else {
		log.Fatal("Either -openapi or -openapi-url must be provided")
	}

	log.Printf("Loaded openapi specification, building MCP server")

	s := server.NewMCPServer(
		"OpenAPI MCP Server",
		"1.0.0",
		server.WithLogging(),
	)

	for path, pathItem := range swagger.Paths.Map() {
		log.Printf("Processing path: %s", path)
		for method, operation := range pathItem.Operations() {
			log.Printf("Processing method: %s", method)
			safePath := stringsutil.ReplaceAll(path, "", "_", "{", "}", "/")
			toolName := strings.ToLower(method) + "-" + safePath
			toolOpts := []mcp.ToolOption{
				mcp.WithDescription(operation.Description),
			}

			// Add path parameters
			for _, param := range pathItem.Parameters {
				log.Printf("processing path parameter: %s", param.Value.Name)
				if param.Value.Schema != nil && param.Value.Schema.Value != nil {
					switch param.Value.Schema.Value.Type {
					case "string":
						toolOpts = append(toolOpts, mcp.WithString(param.Value.Name,
							mcp.Description(param.Value.Description),
							mcp.Required(),
						))
					case "integer", "number":
						toolOpts = append(toolOpts, mcp.WithNumber(param.Value.Name,
							mcp.Description(param.Value.Description),
							mcp.Required(),
						))
					case "boolean":
						toolOpts = append(toolOpts, mcp.WithString(param.Value.Name,
							mcp.Description(param.Value.Description),
							mcp.Required(),
						))
					}
				}
			}

			var toolOptions []string

			// Add operation parameters
			for _, param := range operation.Parameters {
				log.Printf("processing operation parameter: %s", param.Value.Name)
				if param.Value.Schema != nil && param.Value.Schema.Value != nil {
					switch param.Value.Schema.Value.Type {
					case "string":
						toolOpts = append(toolOpts, mcp.WithString(param.Value.Name,
							mcp.Description(param.Value.Description),
							mcp.Required(),
						))
					case "integer", "number":
						toolOpts = append(toolOpts, mcp.WithNumber(param.Value.Name,
							mcp.Description(param.Value.Description),
							mcp.Required(),
						))
					case "boolean":
						toolOpts = append(toolOpts, mcp.WithString(param.Value.Name,
							mcp.Description(param.Value.Description),
							mcp.Required(),
						))
					}
					toolOptions = append(toolOptions, fmt.Sprintf("Name: %s | Description: %s | Type: %s | Required: %t",
						param.Value.Name,
						param.Value.Description,
						param.Value.Schema.Value.Type,
						param.Value.Required))
				}
			}

			// Add request body parameters if present
			if operation.RequestBody != nil {
				for contentType, mediaType := range operation.RequestBody.Value.Content {
					if strings.Contains(contentType, "json") && mediaType.Schema != nil && mediaType.Schema.Value != nil {
						for propName, prop := range mediaType.Schema.Value.Properties {
							log.Printf("processing body parameter: %s", propName)
							if prop.Value != nil {
								var toolOpt mcp.ToolOption
								switch {
								case prop.Value.Type == "array" && prop.Value.Items != nil && prop.Value.Items.Value.Type == "string":
									// Handle arrays as comma-separated strings
									toolOpt = mcp.WithString(propName,
										mcp.Description(prop.Value.Description+" (comma-separated list)"),
										mcp.Required(),
									)
								case prop.Value.Type == "string":
									toolOpt = mcp.WithString(propName,
										mcp.Description(prop.Value.Description),
										mcp.Required(),
									)
								case prop.Value.Type == "integer" || prop.Value.Type == "number":
									toolOpt = mcp.WithNumber(propName,
										mcp.Description(prop.Value.Description),
										mcp.Required(),
									)
								case prop.Value.Type == "boolean":
									toolOpt = mcp.WithString(propName,
										mcp.Description(prop.Value.Description),
										mcp.Required(),
									)
								}
								if toolOpt != nil {
									toolOptions = append(toolOptions, fmt.Sprintf("Name: %s | Description: %s | Type: %s | Required: %v",
										propName,
										prop.Value.Description,
										prop.Value.Type,
										prop.Value.Required))
									toolOpts = append(toolOpts, toolOpt)
								}
							}
						}
					}
				}
			}

			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("Adding tool %s with options:\n", toolName))
			for _, opt := range toolOptions {
				sb.WriteString(opt + "\n")
			}
			log.Print(sb.String())
			tool := mcp.NewTool(toolName, toolOpts...)

			s.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				// Build the target URL by joining base URL and path
				targetURL := strings.TrimRight(*baseURL, "/") + "/" + strings.TrimLeft(path, "/")

				// Create HTTP request
				httpReq, err := http.NewRequestWithContext(ctx, method, targetURL, nil)
				if err != nil {
					return mcp.NewToolResultError(fmt.Sprintf("Failed to create request: %v", err)), nil
				}

				// Add query parameters
				q := httpReq.URL.Query()
				for name, value := range request.Params.Arguments {
					q.Add(name, fmt.Sprint(value))
				}
				httpReq.URL.RawQuery = q.Encode()

				// If this is a POST/PUT/PATCH, add request body
				if operation.RequestBody != nil && (method == "POST" || method == "PUT" || method == "PATCH") {
					requestBody := make(map[string]interface{})
					for key, value := range request.Params.Arguments {
						// Check if this parameter is defined as an array in the schema
						if strValue, ok := value.(string); ok {
							if mediaType := operation.RequestBody.Value.Content["application/json"]; mediaType != nil {
								if prop, ok := mediaType.Schema.Value.Properties[key]; ok && prop.Value.Type == "array" {
									// Split comma-separated string into array, trimming spaces
									values := strings.Split(strValue, ",")
									for i := range values {
										values[i] = strings.TrimSpace(values[i])
									}
									requestBody[key] = values
									continue
								}
							}
						}
						requestBody[key] = value
					}

					body, err := json.Marshal(requestBody)
					if err != nil {
						return mcp.NewToolResultError(fmt.Sprintf("Failed to marshal request body: %v", err)), nil
					}
					httpReq.Body = io.NopCloser(bytes.NewReader(body))
					httpReq.Header.Set("Content-Type", "application/json")
				}

				// Make the request
				client := &http.Client{}
				log.Printf("Making %s request to %s", method, targetURL)
				resp, err := client.Do(httpReq)
				if err != nil {
					log.Printf("Request failed: %v", err)
					return mcp.NewToolResultError(fmt.Sprintf("Request failed: %v", err)), nil
				}
				defer func() {
					_ = resp.Body.Close()
				}()

				// Read response body
				respBody, err := io.ReadAll(resp.Body)
				if err != nil {
					log.Printf("Failed to read response: %v", err)
					return mcp.NewToolResultError(fmt.Sprintf("Failed to read response: %v", err)), nil
				}

				// If response is not successful, return error with details
				if resp.StatusCode >= 400 {
					log.Printf("API error %d: %s", resp.StatusCode, string(respBody))
					return mcp.NewToolResultError(fmt.Sprintf("API returned %s (%d): %s",
						resp.Status, resp.StatusCode, string(respBody))), nil
				}

				log.Printf("Request successful: %s", resp.Status)

				// Return successful response
				return mcp.NewToolResultText(string(respBody)), nil
			})
		}
	}

	if err := server.ServeStdio(s); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
