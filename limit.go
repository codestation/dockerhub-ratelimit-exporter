// Copyright 2025 codestation. All rights reserved.
// Use of this source code is governed by a MIT-license
// that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	DockerHubTokenURL     = "https://auth.docker.io/token?service=registry.docker.io&scope=repository:ratelimitpreview/test:pull"
	DockerHubRateLimitURL = "https://registry-1.docker.io/v2/ratelimitpreview/test/manifests/latest"
	DefaultHTTPTimeout    = 5 * time.Second
)

type tokenResponse struct {
	Token string `json:"token"`
}

type rateLimitResponse struct {
	Remaining int `json:"remaining"`
	Limit     int `json:"limit"`
}

func getAuthToken(client *http.Client, credentials string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, DockerHubTokenURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	if credentials != "" {
		req.Header.Set("Authorization", "Basic "+credentials)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute request: %w", err)
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			slog.Error("Failed to close HTTP response", "error", err)
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch auth token, status code: %d", resp.StatusCode)
	}

	var token tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return token.Token, nil
}

func parseRateLimitHeader(headers http.Header, headerKey string) (int, error) {
	headerValue := headers.Get(headerKey)
	if headerValue == "" {
		return 0, fmt.Errorf("missing %s header", headerKey)
	}

	matches := strings.Split(headerValue, ";")
	value, err := strconv.Atoi(matches[0])
	if err != nil {
		return 0, err
	}

	return value, nil
}

func getRateLimit(client *http.Client, token string) (*rateLimitResponse, error) {
	req, err := http.NewRequest(http.MethodHead, DockerHubRateLimitURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			slog.Error("Failed to close HTTP response", "error", err)
		}
	}(resp.Body)

	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		slog.Error("Failed to discard response body", "error", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch auth token, status code: %d", resp.StatusCode)
	}

	limit, err := parseRateLimitHeader(resp.Header, "ratelimit-limit")
	if err != nil {
		return nil, fmt.Errorf("failed to parse rate limit header: %w", err)
	}

	remaining, err := parseRateLimitHeader(resp.Header, "ratelimit-remaining")
	if err != nil {
		return nil, fmt.Errorf("failed to parse rate limit header: %w", err)
	}

	return &rateLimitResponse{
		Remaining: remaining,
		Limit:     limit,
	}, nil
}
