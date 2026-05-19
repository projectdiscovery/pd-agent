package natsrpc

import (
	"testing"

	json "github.com/json-iterator/go"
)

func TestStripJSONNul(t *testing.T) {
	nulEsc := "\\u0000"
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "no nul",
			in:   `{"response":"hello"}`,
			want: `{"response":"hello"}`,
		},
		{
			name: "single nul in middle",
			in:   `{"response":"hel` + nulEsc + `lo"}`,
			want: `{"response":"hello"}`,
		},
		{
			name: "multiple nuls",
			in:   `{"response":"` + nulEsc + `he` + nulEsc + `llo` + nulEsc + `"}`,
			want: `{"response":"hello"}`,
		},
		{
			name: "preserves other escapes",
			in:   `{"response":"a\nb` + nulEsc + `cd"}`,
			want: `{"response":"a\nbcd"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripJSONNul([]byte(tt.in), "test-method")
			if string(got) != tt.want {
				t.Errorf("got %s, want %s", string(got), tt.want)
			}
		})
	}
}

// Marshaling a struct with a NUL in a string produces the 6-byte JSON
// escape; the strip removes it and the result still parses.
func TestStripJSONNul_RoundtripThroughMarshal(t *testing.T) {
	type Payload struct {
		Response string `json:"response"`
	}
	p := Payload{Response: "raw\x00bytes\x00here"}

	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	cleaned := stripJSONNul(data, "test")

	var out Payload
	if err := json.Unmarshal(cleaned, &out); err != nil {
		t.Fatalf("cleaned JSON does not parse: %v (data=%s)", err, cleaned)
	}
	if out.Response != "rawbyteshere" {
		t.Errorf("got %q, want %q", out.Response, "rawbyteshere")
	}
}
