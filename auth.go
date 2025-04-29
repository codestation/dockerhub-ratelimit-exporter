// Copyright 2025 codestation. All rights reserved.
// Use of this source code is governed by a MIT-license
// that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

type authConfig struct {
	Auths map[string]authEntry `json:"auths"`
}

type authEntry struct {
	Auth string `json:"auth"`
}

func readAuthFile(dockerConfig string) (string, error) {
	config := authConfig{Auths: map[string]authEntry{}}

	f, err := os.Open(dockerConfig)
	if err != nil {
		return "", fmt.Errorf("cannot open auth file: %w", err)
	}

	defer func(f *os.File) {
		errClose := f.Close()
		if errClose != nil {
			slog.Error("Cannot close auth file", "error", errClose)
		}
	}(f)

	if err := json.NewDecoder(f).Decode(&config); err != nil {
		return "", fmt.Errorf("cannot parse auth file: %w", err)
	}

	for key, auth := range config.Auths {
		if strings.HasPrefix(key, "https://index.docker.io/v1") {
			return auth.Auth, nil
		}
	}

	return "", fmt.Errorf("cannot find DockerHub credentials")
}
