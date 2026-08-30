package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOpenAINonStreamingResponseCompletedRequiresSuccessfulTerminal(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{name: "responses completed with null error", body: `{"id":"resp_1","object":"response","status":"completed","error":null,"output":[]}`, want: true},
		{name: "responses failed", body: `{"id":"resp_1","object":"response","status":"failed","error":{"message":"failed"}}`},
		{name: "responses incomplete", body: `{"id":"resp_1","object":"response","status":"incomplete","error":null}`},
		{name: "responses cancelled", body: `{"id":"resp_1","object":"response","status":"cancelled","error":null}`},
		{name: "chat completion", body: `{"id":"chatcmpl_1","object":"chat.completion","choices":[{"finish_reason":"stop"}]}`, want: true},
		{name: "chat null error", body: `{"id":"chatcmpl_1","object":"chat.completion","error":null,"choices":[{"finish_reason":"stop"}]}`, want: true},
		{name: "chat error", body: `{"id":"chatcmpl_1","object":"chat.completion","error":{"message":"failed"},"choices":[{"finish_reason":"stop"}]}`},
		{name: "chat choice lacks terminal", body: `{"id":"chatcmpl_1","object":"chat.completion","choices":[{}]}`},
		{name: "chat missing choices", body: `{"id":"chatcmpl_1","object":"chat.completion","choices":[]}`},
		{name: "status without response envelope", body: `{"status":"completed","error":null}`},
		{name: "invalid json", body: `{`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, openAINonStreamingResponseCompleted([]byte(tt.body)))
		})
	}
}
