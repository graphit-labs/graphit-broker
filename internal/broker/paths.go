package broker

import (
	"os"
	"path/filepath"
	"strings"
)

var brokerProcessStartDir, _ = os.Getwd()

func absolutePathFromStart(path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Join(brokerProcessStartDir, path)
}

func graphitGlobalDir() string {
	if override := strings.TrimSpace(os.Getenv("GRAPHIT_GLOBAL_DIR")); override != "" {
		return absolutePathFromStart(override)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".graphit")
}

func brokerGlobalPath(elements ...string) string {
	globalDir := graphitGlobalDir()
	if globalDir == "" {
		return ""
	}
	parts := append([]string{globalDir, "broker"}, elements...)
	return filepath.Join(parts...)
}

// DefaultConfigPath returns the platform-native location of the broker configuration.
func DefaultConfigPath() string { return brokerGlobalPath("config.yaml") }
