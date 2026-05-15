package runtools

import (
	"context"
	"testing"
)

func TestRunNaabu_RequiresOutputFile(t *testing.T) {
	_, err := RunNaabu(context.Background(), []string{"127.0.0.1"}, NaabuOptions{})
	if err == nil {
		t.Fatal("expected error when OutputFile is empty")
	}
}
