// Copyright 2025 codestation. All rights reserved.
// Use of this source code is governed by a MIT-license
// that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	flag "github.com/spf13/pflag"
)

const (
	DefaultInterval = 1 * time.Minute
)

var dockerHubLimit = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "dockerhub_limit_max_requests_total",
	Help: "DockerHub Maximum request limit",
})

var dockerHubRemaining = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "dockerhub_limit_remaining_requests_total",
	Help: "DockerHub remaining request limit",
})

func updateMetrics(client *http.Client, credentials string) error {
	token, err := getAuthToken(client, credentials)
	if err != nil {
		return fmt.Errorf("failed to get auth token: %w", err)
	}

	rateLimit, err := getRateLimit(client, token)
	if err != nil {
		return fmt.Errorf("failed to get rate limit: %w", err)
	}

	dockerHubLimit.Set(float64(rateLimit.Limit))
	dockerHubRemaining.Set(float64(rateLimit.Remaining))

	slog.Info("Limits",
		"limit", rateLimit.Limit,
		"remaining", rateLimit.Remaining,
	)

	return nil
}

func main() {
	f := flag.NewFlagSet("dockerhub-ratelimit-exporter", flag.ContinueOnError)

	f.Usage = func() {
		fmt.Println(f.FlagUsages())
		os.Exit(0)
	}

	f.StringP("listen", "l", ":9123", "Listen address")
	f.StringP("config", "c", "", "path to Docker config.json")
	f.StringP("username", "u", "", "DockerHub username")
	f.StringP("token", "t", "", "DockerHub token")
	f.Duration("client-timeout", DefaultHTTPTimeout, "HTTP client timeout")
	f.DurationP("interval", "i", DefaultInterval, "Default interval")

	if err := f.Parse(os.Args[1:]); err != nil {
		slog.Error("Cannot parse args", "error", err)
		os.Exit(1)
	}

	configPath, err := f.GetString("config")
	if err != nil {
		slog.Error("Cannot get config path", "error", err)
		os.Exit(1)
	}

	var dockerCredentials string

	if configPath == "" {
		username, err := f.GetString("username")
		if err != nil {
			slog.Error("Cannot get username", "error", err)
			os.Exit(1)
		}

		token, err := f.GetString("token")
		if err != nil {
			slog.Error("Cannot get token", "error", err)
		}

		if username != "" && token != "" {
			credentials := fmt.Sprintf("%s:%s", username, token)
			dockerCredentials = base64.URLEncoding.EncodeToString([]byte(credentials))
		} else {
			slog.Info("No config file or credentials specified, using anonymous check")
		}
	} else {
		credentials, err := readAuthFile(configPath)
		if err != nil {
			slog.Error("Failed to read Docker credentials", "error", err)
		}

		dockerCredentials = credentials
	}

	timeout, err := f.GetDuration("client-timeout")
	if err != nil {
		slog.Error("Cannot get client timeout", "error", err)
	}
	client := &http.Client{Timeout: timeout}

	interval, err := f.GetDuration("interval")
	if err != nil {
		slog.Error("Cannot get interval", "error", err)
	}

	go func() {
		for {
			if err := updateMetrics(client, dockerCredentials); err != nil {
				slog.Error("Failed to update metrics", "error", err)
			}
			time.Sleep(interval)
		}
	}()

	addr, err := f.GetString("listen")
	if err != nil {
		slog.Error("Cannot get listen address", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	reg := prometheus.NewRegistry()
	reg.MustRegister(dockerHubLimit)
	reg.MustRegister(dockerHubRemaining)

	handler := promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg})
	mux.Handle("/metrics", handler)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, http.StatusText(http.StatusOK), http.StatusOK)
	})

	server := http.Server{Addr: addr, Handler: mux}

	slog.Info("Starting HTTP server", "address", addr)

	go func() {
		slog.Info("Server started", "address", addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("Error starting server", "error", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	httpCtx, httpCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer httpCancel()

	if err := server.Shutdown(httpCtx); err != nil {
		slog.Error("Error during HTTP server shutdown", "error", err)
	} else {
		slog.Info("HTTP server gracefully stopped")
	}
}
