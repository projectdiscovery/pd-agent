package types

// ToolType represents the type of tool to execute
type ToolType int

const (
	Nuclei ToolType = iota
	Dnsx
	Shuffledns
	Naabu
	Httpx
	Katana
)

func (t ToolType) String() string {
	switch t {
	case Nuclei:
		return "nuclei"
	case Dnsx:
		return "dnsx"
	case Shuffledns:
		return "shuffledns"
	case Naabu:
		return "naabu"
	case Httpx:
		return "httpx"
	case Katana:
		return "katana"
	default:
		return "unknown"
	}
}

type Task struct {
	Tool    ToolType
	Options Options

	Id string
}

type Options struct {
	// Common options
	Hosts  []string
	Silent bool

	// - Nuclei
	Templates []string

	ScanID        string
	EnumerationID string
	TeamID        string
}
