package scanners

import (
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/JAugusto42/shield-ast/internal/downloader"
)

func SetupTrufflehog(cacheDir string) (string, error) {
	// TruffleHog uses "darwin", "linux", "windows" and "amd64", "arm64" natively
	// It matches the runtime.GOOS and runtime.GOARCH of Go directly in their release tags

	version := "3.95.9"
	osName := runtime.GOOS
	arch := runtime.GOARCH

	// TruffleHog naming convention: trufflehog_3.95.9_linux_amd64.tar.gz
	fileName := fmt.Sprintf("trufflehog_%s_%s_%s.tar.gz", version, osName, arch)
	downloadURL := fmt.Sprintf("https://github.com/trufflesecurity/trufflehog/releases/download/v%s/%s", version, fileName)

	// Define the expected binary name
	binaryName := "trufflehog"
	if osName == "windows" {
		binaryName = "trufflehog.exe"
	}

	destPath := filepath.Join(cacheDir, binaryName)

	err := downloader.DownloadAndExtractTarGz(downloadURL, destPath, binaryName)
	if err != nil {
		return "", fmt.Errorf("failed to download TruffleHog: %w", err)
	}

	return destPath, nil
}
