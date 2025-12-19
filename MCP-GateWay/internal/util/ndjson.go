package util

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

type NDJSON struct {
	w  io.Writer
	mu sync.Mutex
}

func NewNDJSON(w io.Writer) *NDJSON { return &NDJSON{w: w} }

// WriteLine: obj에 ts 추가해서 한 줄 JSON으로 기록
func (n *NDJSON) WriteLine(obj map[string]any) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	obj["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
	b, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(n.w, string(b))
	return err
}
