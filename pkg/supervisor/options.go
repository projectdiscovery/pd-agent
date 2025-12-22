package supervisor

// ConvertOptions converts main.Options to supervisor.AgentOptions
// This is a helper function to bridge between the main package and supervisor package
func ConvertOptions(options interface{}) *AgentOptions {
	// Use reflection or type assertion - for now we'll use a function that accepts the needed fields
	// This avoids importing the main package
	return nil // Will be implemented via a callback pattern
}

