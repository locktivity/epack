package exec

import (
	"bytes"
	"testing"
)

func TestParseProgressLine(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantOK  bool
		wantMsg ProgressMessage
	}{
		{
			name:   "valid status message",
			input:  []byte(`{"type":"epack_progress","protocol_version":1,"kind":"status","message":"Connecting..."}`),
			wantOK: true,
			wantMsg: ProgressMessage{
				Type:            "epack_progress",
				ProtocolVersion: 1,
				Kind:            "status",
				Message:         "Connecting...",
			},
		},
		{
			name:   "valid progress message with current/total",
			input:  []byte(`{"type":"epack_progress","protocol_version":1,"kind":"progress","message":"Fetching","current":5,"total":100}`),
			wantOK: true,
			wantMsg: ProgressMessage{
				Type:            "epack_progress",
				ProtocolVersion: 1,
				Kind:            "progress",
				Message:         "Fetching",
				Current:         5,
				Total:           100,
			},
		},
		{
			name:   "empty line",
			input:  []byte(""),
			wantOK: false,
		},
		{
			name:   "non-JSON text",
			input:  []byte("some plain text"),
			wantOK: false,
		},
		{
			name:   "JSON but not progress type",
			input:  []byte(`{"type":"epack_result","protocol_version":1,"data":{}}`),
			wantOK: false,
		},
		{
			name:   "JSON object without type",
			input:  []byte(`{"message":"hello"}`),
			wantOK: false,
		},
		{
			name:   "invalid JSON",
			input:  []byte(`{"type":"epack_progress"`),
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, ok := parseProgressLine(tt.input)
			if ok != tt.wantOK {
				t.Errorf("parseProgressLine() ok = %v, want %v", ok, tt.wantOK)
			}
			if tt.wantOK {
				if msg.Type != tt.wantMsg.Type {
					t.Errorf("Type = %v, want %v", msg.Type, tt.wantMsg.Type)
				}
				if msg.Kind != tt.wantMsg.Kind {
					t.Errorf("Kind = %v, want %v", msg.Kind, tt.wantMsg.Kind)
				}
				if msg.Message != tt.wantMsg.Message {
					t.Errorf("Message = %v, want %v", msg.Message, tt.wantMsg.Message)
				}
				if msg.Current != tt.wantMsg.Current {
					t.Errorf("Current = %v, want %v", msg.Current, tt.wantMsg.Current)
				}
				if msg.Total != tt.wantMsg.Total {
					t.Errorf("Total = %v, want %v", msg.Total, tt.wantMsg.Total)
				}
			}
		})
	}
}

func TestStreamingStdoutWriter(t *testing.T) {
	t.Run("parses progress messages and accumulates result", func(t *testing.T) {
		var progressMsgs []ProgressMessage
		w := newStreamingStdoutWriter(func(msg ProgressMessage) {
			progressMsgs = append(progressMsgs, msg)
		})

		// Write progress message followed by result
		input := `{"type":"epack_progress","protocol_version":1,"kind":"status","message":"Working..."}
{"type":"epack_result","protocol_version":1,"data":{"key":"value"}}
`
		_, _ = w.Write([]byte(input))

		// Should have captured one progress message
		if len(progressMsgs) != 1 {
			t.Errorf("got %d progress messages, want 1", len(progressMsgs))
		}
		if progressMsgs[0].Message != "Working..." {
			t.Errorf("progress message = %q, want %q", progressMsgs[0].Message, "Working...")
		}

		// Result should contain only the non-progress line
		result := w.Result()
		expected := `{"type":"epack_result","protocol_version":1,"data":{"key":"value"}}
`
		if string(result) != expected {
			t.Errorf("Result() = %q, want %q", string(result), expected)
		}
	})

	t.Run("handles partial lines", func(t *testing.T) {
		var progressMsgs []ProgressMessage
		w := newStreamingStdoutWriter(func(msg ProgressMessage) {
			progressMsgs = append(progressMsgs, msg)
		})

		// Write in chunks
		_, _ = w.Write([]byte(`{"type":"epack_pro`))
		_, _ = w.Write([]byte(`gress","protocol_version":1,"kind":"status","message":"Hi"}`))
		_, _ = w.Write([]byte("\n"))

		if len(progressMsgs) != 1 {
			t.Errorf("got %d progress messages, want 1", len(progressMsgs))
		}
	})

	t.Run("accumulates non-progress output", func(t *testing.T) {
		w := newStreamingStdoutWriter(nil) // No callback

		input := `some debug output
{"type":"epack_result","protocol_version":1,"data":{}}
`
		_, _ = w.Write([]byte(input))

		result := w.Result()
		if !bytes.Contains(result, []byte("some debug output")) {
			t.Errorf("Result should contain non-progress output")
		}
		if !bytes.Contains(result, []byte("epack_result")) {
			t.Errorf("Result should contain result line")
		}
	})

	t.Run("handles nil callback", func(t *testing.T) {
		w := newStreamingStdoutWriter(nil)

		// Should not panic
		_, _ = w.Write([]byte(`{"type":"epack_progress","protocol_version":1,"kind":"status","message":"Hi"}` + "\n"))

		// Result should be empty (progress was filtered out)
		result := w.Result()
		if len(result) != 0 {
			t.Errorf("Result should be empty when only progress was written, got %q", string(result))
		}
	})
}
