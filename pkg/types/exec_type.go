package types

var AllTools = []ToolType{}

func init() {
	for i := 0; i < int(Katana); i++ {
		AllTools = append(AllTools, ToolType(i))
	}
}

// ToolType identifies a scanner tool.
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

	Result *TaskResult

	Id string
}

type TaskResult struct {
	Stdout string
	Stderr string
	Error  error
}

type Options struct {
	Hosts  []string
	Silent bool
	TeamID string
	Output string

	// Nuclei
	ScanID       string
	Templates    []string
	Config       string
	ReportConfig string // base64 nuclei reporting config (Jira/Linear/GitHub tracker)
	HistoryID    int64

	// Enumeration
	EnumerationID string
	Steps         []string
}
