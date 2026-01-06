package ai

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/pkg/logger"
)

// LLMClient provides access to large language model APIs
type LLMClient struct {
	httpClient   *http.Client
	logger       *logger.Logger
	config       LLMConfig
}

// LLMConfig holds LLM client configuration
type LLMConfig struct {
	Provider       string  // claude, openai
	ClaudeAPIKey   string
	OpenAIAPIKey   string
	Model          string  // claude-3-sonnet-20240229, gpt-4-turbo, etc.
	Temperature    float64
	MaxTokens      int
	VisionEnabled  bool
	SystemPrompt   string
	Timeout        time.Duration
}

// NewLLMClient creates a new LLM client
func NewLLMClient(cfg LLMConfig, log *logger.Logger) *LLMClient {
	if cfg.Timeout == 0 {
		cfg.Timeout = 60 * time.Second
	}
	if cfg.Temperature == 0 {
		cfg.Temperature = 0.3 // Low temperature for factual analysis
	}
	if cfg.MaxTokens == 0 {
		cfg.MaxTokens = 4096
	}
	if cfg.Model == "" {
		if cfg.Provider == "claude" {
			cfg.Model = "claude-3-sonnet-20240229"
		} else {
			cfg.Model = "gpt-4-turbo"
		}
	}

	return &LLMClient{
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
		logger: log.WithComponent("llm-client"),
		config: cfg,
	}
}

// Message represents a chat message
type Message struct {
	Role    string        `json:"role"`
	Content []ContentPart `json:"content"`
}

// ContentPart represents a part of message content (text or image)
type ContentPart struct {
	Type      string       `json:"type"`
	Text      string       `json:"text,omitempty"`
	ImageURL  *ImageURL    `json:"image_url,omitempty"`  // OpenAI format
	Source    *ImageSource `json:"source,omitempty"`     // Claude format
}

// ImageURL for OpenAI format
type ImageURL struct {
	URL    string `json:"url"`
	Detail string `json:"detail,omitempty"` // low, high, auto
}

// ImageSource for Claude format
type ImageSource struct {
	Type      string `json:"type"` // base64
	MediaType string `json:"media_type"`
	Data      string `json:"data"`
}

// CompletionRequest represents a completion request
type CompletionRequest struct {
	Messages    []Message `json:"messages"`
	System      string    `json:"system,omitempty"`
	MaxTokens   int       `json:"max_tokens"`
	Temperature float64   `json:"temperature"`
	Model       string    `json:"model"`
}

// CompletionResponse represents a completion response
type CompletionResponse struct {
	Content    string `json:"content"`
	StopReason string `json:"stop_reason"`
	Usage      struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

// AnalyzeForScam sends content to LLM for scam analysis
func (c *LLMClient) AnalyzeForScam(ctx context.Context, req *models.ScamAnalysisRequest) (*LLMScamAnalysis, error) {
	startTime := time.Now()

	// Build the prompt
	systemPrompt := c.getScamDetectionSystemPrompt()
	userPrompt := c.buildScamAnalysisPrompt(req)

	// Prepare messages
	messages := []Message{
		{
			Role: "user",
			Content: []ContentPart{
				{Type: "text", Text: userPrompt},
			},
		},
	}

	// Add image if present
	if len(req.ImageData) > 0 && c.config.VisionEnabled {
		mediaType := "image/png"
		if isJPEG(req.ImageData) {
			mediaType = "image/jpeg"
		}

		imageContent := ContentPart{
			Type: "image",
		}

		if c.config.Provider == "claude" {
			imageContent.Source = &ImageSource{
				Type:      "base64",
				MediaType: mediaType,
				Data:      base64.StdEncoding.EncodeToString(req.ImageData),
			}
		} else {
			// OpenAI format
			imageContent.Type = "image_url"
			imageContent.ImageURL = &ImageURL{
				URL:    fmt.Sprintf("data:%s;base64,%s", mediaType, base64.StdEncoding.EncodeToString(req.ImageData)),
				Detail: "high",
			}
		}

		messages[0].Content = append(messages[0].Content, imageContent)
	}

	// Make the API call
	var response *CompletionResponse
	var err error

	switch c.config.Provider {
	case "claude":
		response, err = c.callClaude(ctx, systemPrompt, messages)
	case "openai":
		response, err = c.callOpenAI(ctx, systemPrompt, messages)
	default:
		return nil, fmt.Errorf("unsupported LLM provider: %s", c.config.Provider)
	}

	if err != nil {
		return nil, err
	}

	// Parse the response
	analysis, err := c.parseLLMResponse(response.Content)
	if err != nil {
		c.logger.Warn().Err(err).Msg("failed to parse LLM response, returning raw")
		analysis = &LLMScamAnalysis{
			RawResponse: response.Content,
		}
	}

	analysis.ProcessingTime = time.Since(startTime).String()
	analysis.ModelUsed = c.config.Model
	analysis.TokensUsed = response.Usage.InputTokens + response.Usage.OutputTokens

	return analysis, nil
}

// LLMScamAnalysis represents the parsed LLM analysis
type LLMScamAnalysis struct {
	IsScam          bool                    `json:"is_scam"`
	Confidence      float64                 `json:"confidence"`
	ScamType        models.ScamType         `json:"scam_type"`
	Severity        models.ScamSeverity     `json:"severity"`
	Explanation     string                  `json:"explanation"`
	RedFlags        []string                `json:"red_flags"`
	Indicators      []models.ScamIndicator  `json:"indicators"`
	SafetyTips      []string                `json:"safety_tips"`
	Intent          string                  `json:"intent"`
	ManipulationTactics []string            `json:"manipulation_tactics"`
	RawResponse     string                  `json:"raw_response,omitempty"`
	ProcessingTime  string                  `json:"processing_time"`
	ModelUsed       string                  `json:"model_used"`
	TokensUsed      int                     `json:"tokens_used"`
}

// getScamDetectionSystemPrompt returns the system prompt for scam detection
func (c *LLMClient) getScamDetectionSystemPrompt() string {
	return `You are an expert scam detection AI assistant. Your role is to analyze messages, images, URLs, and other content to identify potential scams, fraud, and phishing attempts.

## Your Expertise Includes:
- Phishing and social engineering detection
- Financial scam patterns (advance fee fraud, investment scams, crypto scams)
- Romance/dating scams
- Tech support scams
- Impersonation scams (CEO fraud, government impersonation)
- Job offer scams
- Prize/lottery scams
- Multi-language scam detection (Arabic, Persian, Hindi, Chinese, etc.)

## Analysis Guidelines:
1. Look for urgency tactics ("Act now!", "Limited time!")
2. Check for emotional manipulation (fear, greed, romance)
3. Identify requests for money, gift cards, or cryptocurrency
4. Spot grammatical errors and awkward phrasing
5. Recognize impersonation of trusted brands/authorities
6. Detect suspicious URLs and domains
7. Identify requests for personal/financial information

## Response Format:
Respond in valid JSON format with this structure:
{
  "is_scam": boolean,
  "confidence": 0.0-1.0,
  "scam_type": "phishing|advance_fee|romance|tech_support|investment|impersonation|job_offer|shipping|tax_refund|prize_winning|banking|crypto|sextortion|other|none",
  "severity": "critical|high|medium|low|none",
  "explanation": "Brief explanation of why this is or isn't a scam",
  "red_flags": ["list of red flags found"],
  "safety_tips": ["actionable safety advice"],
  "intent": "The apparent intent of the message",
  "manipulation_tactics": ["psychological tactics used"]
}

Be thorough but concise. When in doubt, err on the side of caution.`
}

// buildScamAnalysisPrompt builds the user prompt for scam analysis
func (c *LLMClient) buildScamAnalysisPrompt(req *models.ScamAnalysisRequest) string {
	var sb strings.Builder

	sb.WriteString("Analyze the following content for potential scam or fraud:\n\n")

	// Content type
	sb.WriteString(fmt.Sprintf("**Content Type:** %s\n", req.ContentType))

	// Source
	if req.Source != "" {
		sb.WriteString(fmt.Sprintf("**Source:** %s\n", req.Source))
	}

	// Sender info
	if req.SenderInfo != nil {
		sb.WriteString("\n**Sender Information:**\n")
		if req.SenderInfo.PhoneNumber != "" {
			sb.WriteString(fmt.Sprintf("- Phone: %s\n", req.SenderInfo.PhoneNumber))
		}
		if req.SenderInfo.Email != "" {
			sb.WriteString(fmt.Sprintf("- Email: %s\n", req.SenderInfo.Email))
		}
		if req.SenderInfo.DisplayName != "" {
			sb.WriteString(fmt.Sprintf("- Name: %s\n", req.SenderInfo.DisplayName))
		}
		if req.SenderInfo.Country != "" {
			sb.WriteString(fmt.Sprintf("- Country: %s\n", req.SenderInfo.Country))
		}
		sb.WriteString(fmt.Sprintf("- Is Contact: %v\n", req.SenderInfo.IsContact))
	}

	// Main content
	sb.WriteString("\n**Content to Analyze:**\n```\n")
	sb.WriteString(req.Content)
	sb.WriteString("\n```\n")

	// URL if present
	if req.URL != "" {
		sb.WriteString(fmt.Sprintf("\n**URL:** %s\n", req.URL))
	}

	// Context
	if req.Context != "" {
		sb.WriteString(fmt.Sprintf("\n**Additional Context:** %s\n", req.Context))
	}

	// Language hint
	if req.Language != "" {
		sb.WriteString(fmt.Sprintf("\n**Language:** %s\n", req.Language))
	}

	sb.WriteString("\nProvide your analysis in JSON format.")

	return sb.String()
}

// callClaude makes a request to Claude API
func (c *LLMClient) callClaude(ctx context.Context, system string, messages []Message) (*CompletionResponse, error) {
	url := "https://api.anthropic.com/v1/messages"

	// Convert messages to Claude format
	claudeMessages := make([]map[string]interface{}, len(messages))
	for i, msg := range messages {
		content := make([]map[string]interface{}, len(msg.Content))
		for j, part := range msg.Content {
			switch part.Type {
			case "text":
				content[j] = map[string]interface{}{
					"type": "text",
					"text": part.Text,
				}
			case "image":
				if part.Source != nil {
					content[j] = map[string]interface{}{
						"type": "image",
						"source": map[string]string{
							"type":       part.Source.Type,
							"media_type": part.Source.MediaType,
							"data":       part.Source.Data,
						},
					}
				}
			}
		}
		claudeMessages[i] = map[string]interface{}{
			"role":    msg.Role,
			"content": content,
		}
	}

	reqBody := map[string]interface{}{
		"model":       c.config.Model,
		"max_tokens":  c.config.MaxTokens,
		"temperature": c.config.Temperature,
		"system":      system,
		"messages":    claudeMessages,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.config.ClaudeAPIKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Claude API error %d: %s", resp.StatusCode, string(body))
	}

	// Parse Claude response
	var claudeResp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
		Usage      struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}

	if err := json.Unmarshal(body, &claudeResp); err != nil {
		return nil, err
	}

	var content string
	for _, c := range claudeResp.Content {
		if c.Type == "text" {
			content += c.Text
		}
	}

	return &CompletionResponse{
		Content:    content,
		StopReason: claudeResp.StopReason,
		Usage: struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		}{
			InputTokens:  claudeResp.Usage.InputTokens,
			OutputTokens: claudeResp.Usage.OutputTokens,
		},
	}, nil
}

// callOpenAI makes a request to OpenAI API
func (c *LLMClient) callOpenAI(ctx context.Context, system string, messages []Message) (*CompletionResponse, error) {
	url := "https://api.openai.com/v1/chat/completions"

	// Convert messages to OpenAI format
	openAIMessages := []map[string]interface{}{
		{
			"role":    "system",
			"content": system,
		},
	}

	for _, msg := range messages {
		content := make([]map[string]interface{}, len(msg.Content))
		for j, part := range msg.Content {
			switch part.Type {
			case "text":
				content[j] = map[string]interface{}{
					"type": "text",
					"text": part.Text,
				}
			case "image_url":
				if part.ImageURL != nil {
					content[j] = map[string]interface{}{
						"type": "image_url",
						"image_url": map[string]string{
							"url":    part.ImageURL.URL,
							"detail": part.ImageURL.Detail,
						},
					}
				}
			}
		}
		openAIMessages = append(openAIMessages, map[string]interface{}{
			"role":    msg.Role,
			"content": content,
		})
	}

	reqBody := map[string]interface{}{
		"model":       c.config.Model,
		"max_tokens":  c.config.MaxTokens,
		"temperature": c.config.Temperature,
		"messages":    openAIMessages,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.config.OpenAIAPIKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OpenAI API error %d: %s", resp.StatusCode, string(body))
	}

	// Parse OpenAI response
	var openAIResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}

	if err := json.Unmarshal(body, &openAIResp); err != nil {
		return nil, err
	}

	if len(openAIResp.Choices) == 0 {
		return nil, fmt.Errorf("no response from OpenAI")
	}

	return &CompletionResponse{
		Content:    openAIResp.Choices[0].Message.Content,
		StopReason: openAIResp.Choices[0].FinishReason,
		Usage: struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		}{
			InputTokens:  openAIResp.Usage.PromptTokens,
			OutputTokens: openAIResp.Usage.CompletionTokens,
		},
	}, nil
}

// parseLLMResponse parses the JSON response from the LLM
func (c *LLMClient) parseLLMResponse(content string) (*LLMScamAnalysis, error) {
	// Try to extract JSON from the response
	content = strings.TrimSpace(content)

	// Handle markdown code blocks
	if strings.HasPrefix(content, "```json") {
		content = strings.TrimPrefix(content, "```json")
		content = strings.TrimSuffix(content, "```")
		content = strings.TrimSpace(content)
	} else if strings.HasPrefix(content, "```") {
		content = strings.TrimPrefix(content, "```")
		content = strings.TrimSuffix(content, "```")
		content = strings.TrimSpace(content)
	}

	// Find JSON in response
	startIdx := strings.Index(content, "{")
	endIdx := strings.LastIndex(content, "}")
	if startIdx != -1 && endIdx != -1 && endIdx > startIdx {
		content = content[startIdx : endIdx+1]
	}

	var analysis LLMScamAnalysis
	if err := json.Unmarshal([]byte(content), &analysis); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return &analysis, nil
}

// NewTextMessage creates a simple text message
func NewTextMessage(role, text string) Message {
	return Message{
		Role: role,
		Content: []ContentPart{
			{Type: "text", Text: text},
		},
	}
}

// Chat sends a chat message and returns the response
func (c *LLMClient) Chat(ctx context.Context, messages []Message, system string) (string, error) {
	if system == "" {
		system = c.config.SystemPrompt
	}

	var response *CompletionResponse
	var err error

	switch c.config.Provider {
	case "claude":
		response, err = c.callClaude(ctx, system, messages)
	case "openai":
		response, err = c.callOpenAI(ctx, system, messages)
	default:
		return "", fmt.Errorf("unsupported provider: %s", c.config.Provider)
	}

	if err != nil {
		return "", err
	}

	return response.Content, nil
}

// Helper functions

func isJPEG(data []byte) bool {
	return len(data) >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF
}
