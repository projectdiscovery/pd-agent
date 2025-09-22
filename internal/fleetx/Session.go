package fleetx

type Session struct {
	// Hosts to scan in the format host:port
	Hosts []Host

	// Tasks to execute on the hosts
	Tasks []Task
}

type AuthenticationProtocol uint8

const (
	AuthenticationProtocolSSH AuthenticationProtocol = iota
	AuthenticationProtocolWinRMI
)

type Authentication struct {
	Protocol AuthenticationProtocol
	Username string
	Password string

	PrivateKeyFile string
}

type TaskResult struct {
	StdOut string
	StdErr string
}
