package fleetx

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	DefaultSSHUsername = "root"
	DefaultSSHPort     = 22
)

// ParseAnsibleInventory reads an Ansible inventory file and returns a list of Hosts
func ParseAnsibleInventory(filename string) ([]Host, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var hosts []Host
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines, comments, and group headers
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}

		// Parse host entry
		parsedHosts, err := parseHostLine(line)
		if err != nil {
			return nil, err
		}

		hosts = append(hosts, parsedHosts...)
	}

	return hosts, scanner.Err()
}

// parseHostLine parses a single line from an Ansible inventory file
func parseHostLine(line string) ([]Host, error) {
	// Split the line into hostname and variables
	parts := strings.SplitN(line, " ", 2)
	if len(parts) == 0 {
		return nil, errors.New("invalid host line")
	}

	// Parse hostname/range pattern
	var hosts []Host
	hostPattern := parts[0]

	// Check if it contains a range pattern [1:3] or [a:c] or [1:10:2]
	if strings.Contains(hostPattern, "[") && strings.Contains(hostPattern, "]") {
		start := strings.Index(hostPattern, "[")
		end := strings.Index(hostPattern, "]")
		if start > 0 && end > start {
			prefix := hostPattern[:start]
			suffix := hostPattern[end+1:]
			rangeStr := hostPattern[start+1 : end]
			rangeParts := strings.Split(rangeStr, ":")

			if len(rangeParts) >= 2 && len(rangeParts) <= 3 {
				// Default increment is 1 if not specified
				increment := 1
				if len(rangeParts) == 3 {
					var err error
					increment, err = strconv.Atoi(rangeParts[2])
					if err != nil {
						return nil, fmt.Errorf("invalid increment: %v", err)
					}
					if increment <= 0 {
						return nil, fmt.Errorf("increment must be positive")
					}
				}

				// Try parsing as numbers first
				startNum, startNumErr := strconv.Atoi(rangeParts[0])
				endNum, endNumErr := strconv.Atoi(rangeParts[1])

				if startNumErr == nil && endNumErr == nil {
					// Numeric range
					for i := startNum; i <= endNum; i += increment {
						address := fmt.Sprintf("%s%d%s", prefix, i, suffix)
						host := Host{
							Address: address,
							Port:    DefaultSSHPort,
							Authentication: Authentication{
								Protocol: AuthenticationProtocolSSH,
								Username: DefaultSSHUsername,
							},
						}
						hosts = append(hosts, host)
					}
				} else if len(rangeParts[0]) == 1 && len(rangeParts[1]) == 1 {
					// Alphabetic range
					startChar := rangeParts[0][0]
					endChar := rangeParts[1][0]
					if startChar <= endChar {
						for c := startChar; c <= endChar; c += uint8(increment) {
							address := fmt.Sprintf("%s%c%s", prefix, c, suffix)
							host := Host{
								Address: address,
								Port:    DefaultSSHPort,
								Authentication: Authentication{
									Protocol: AuthenticationProtocolSSH,
									Username: DefaultSSHUsername,
								},
							}
							hosts = append(hosts, host)
						}
					}
				} else {
					return nil, fmt.Errorf("invalid range format: must be numeric or single letters")
				}
			}
		}
	} else {
		// Single host
		host := Host{
			Address: hostPattern,
			Port:    DefaultSSHPort,
			Authentication: Authentication{
				Protocol: AuthenticationProtocolSSH,
				Username: DefaultSSHUsername,
			},
		}
		hosts = append(hosts, host)
	}

	// Parse ansible_* variables if present
	if len(parts) > 1 {
		vars := parts[1]
		for _, v := range strings.Fields(vars) {
			kv := strings.SplitN(v, "=", 2)
			if len(kv) != 2 {
				continue
			}

			key := strings.TrimSpace(kv[0])
			value := strings.Trim(strings.TrimSpace(kv[1]), "'\"")

			// Apply variables to all hosts in range
			for _, host := range hosts {
				switch key {
				case "ansible_user":
					host.Authentication.Username = value
				case "ansible_port":
					port, err := strconv.Atoi(value)
					if err != nil {
						return nil, err
					}
					host.Port = port
				case "ansible_ssh_private_key_file":
					host.Authentication.PrivateKeyFile = value
				case "ansible_password":
					host.Authentication.Password = value
				}
			}
		}
	}

	return hosts, nil
}
