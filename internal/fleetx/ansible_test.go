package fleetx

import (
	"strings"
	"testing"
)

func TestParseAnsibleInventory(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []Host
		wantErr bool
	}{
		{
			name: "valid inventory with ssh key and password auth",
			input: `[remote_servers]
server1 ansible_host=192.168.1.100 ansible_user=ubuntu ansible_ssh_private_key_file=~/.ssh/id_rsa
server2 ansible_host=192.168.1.101 ansible_user=root ansible_password=MySecretPassword`,
			want: []Host{
				{
					Name: "server1",
					Host: "192.168.1.100",
					Port: DefaultSSHPort,
					Authentication: Authentication{
						Protocol:       AuthenticationProtocolSSH,
						Username:       "ubuntu",
						PrivateKeyFile: "~/.ssh/id_rsa",
					},
				},
				{
					Name: "server2",
					Host: "192.168.1.101",
					Port: DefaultSSHPort,
					Authentication: Authentication{
						Protocol: AuthenticationProtocolSSH,
						Username: "root",
						Password: "MySecretPassword",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid inventory format",
			input: `invalid
format`,
			want:    []Host{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseAnsibleInventory(strings.NewReader(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseAnsibleInventory() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got) != len(tt.want) {
					t.Errorf("ParseAnsibleInventory() got %d hosts, want %d", len(got), len(tt.want))
					return
				}
				for i, host := range got {
					if host != tt.want[i] {
						t.Errorf("Host[%d] = %+v, want %+v", i, host, tt.want[i])
					}
				}
			}
		})
	}
}
