package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/url"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	openapiPath := flag.String("openapi", "", "Path to OpenAPI specification file")
	openapiURL := flag.String("openapi-url", "", "URL to OpenAPI specification")
	flag.Parse()

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
			toolName := strings.ToLower(fmt.Sprintf("%s_%s", method, strings.ReplaceAll(path, "/", "_")))
			toolOpts := []mcp.ToolOption{
				mcp.WithDescription(operation.Description),
			}

			// Add path parameters
			for _, param := range pathItem.Parameters {
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

			// Add operation parameters
			for _, param := range operation.Parameters {
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

			// Add request body parameters if present
			if operation.RequestBody != nil {
				for contentType, mediaType := range operation.RequestBody.Value.Content {
					if strings.Contains(contentType, "json") && mediaType.Schema != nil && mediaType.Schema.Value != nil {
						for propName, prop := range mediaType.Schema.Value.Properties {
							if prop.Value != nil {
								switch prop.Value.Type {
								case "string":
									toolOpts = append(toolOpts, mcp.WithString(propName,
										mcp.Description(prop.Value.Description),
										mcp.Required(),
									))
								case "integer", "number":
									toolOpts = append(toolOpts, mcp.WithNumber(propName,
										mcp.Description(prop.Value.Description),
										mcp.Required(),
									))
								case "boolean":
									toolOpts = append(toolOpts, mcp.WithString(propName,
										mcp.Description(prop.Value.Description),
										mcp.Required(),
									))
								}
							}
						}
					}
				}
			}

			log.Printf("Adding tool %s with opts: %v", toolName, toolOpts)
			tool := mcp.NewTool(toolName, toolOpts...)

			s.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				response := map[string]interface{}{
					"operation": toolName,
					"params":    request.Params.Arguments,
				}

				jsonResponse, err := json.Marshal(response)
				if err != nil {
					return mcp.NewToolResultError(fmt.Sprintf("Failed to marshal response: %v", err)), nil
				}

				return mcp.NewToolResultText(string(jsonResponse)), nil
			})
		}
	}

	if err := server.ServeStdio(s); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
