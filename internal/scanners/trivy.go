package scanners

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/JAugusto42/shield-ast/internal/downloader"
)

const trivyVersion = "v0.72.0"

// SetupTrivy downloads the compressed archive, extracts the binary, and sets permissions.
func SetupTrivy(cacheDir string) (string, error) {
	fileName := getTrivyFileName()
	if fileName == "" {
		return "", fmt.Errorf("unsupported OS or Architecture for Trivy: %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	targetBinary := "trivy"
	if runtime.GOOS == "windows" {
		targetBinary = "trivy.exe"
	}

	finalPath := filepath.Join(cacheDir, targetBinary)

	// [NEW] Cache Verification (Checks for the extracted binary, not the tar.gz)
	if downloader.IsCached(finalPath) {
		if os.Getenv("SHIELD_DEBUG") == "true" {
			log.Printf("[DEBUG] Trivy found in cache: %s", finalPath)
		}
		return finalPath, nil
	}

	url := fmt.Sprintf("https://github.com/aquasecurity/trivy/releases/download/%s/%s", trivyVersion, fileName)
	archivePath := filepath.Join(cacheDir, fileName)

	err := downloader.DownloadFile(url, archivePath)
	if err != nil {
		return "", err
	}

	// Clean up the .tar.gz file after extraction to save disk space
	defer os.Remove(archivePath)

	extractedPath, err := downloader.ExtractTarGzBinary(archivePath, cacheDir, targetBinary)
	if err != nil {
		return "", err
	}

	if runtime.GOOS != "windows" {
		if err := downloader.MakeExecutable(extractedPath); err != nil {
			return "", err
		}
	}

	return extractedPath, nil
}

func getTrivyFileName() string {
	switch runtime.GOOS {
	case "linux":
		if runtime.GOARCH == "amd64" {
			return fmt.Sprintf("trivy_%s_Linux-64bit.tar.gz", trivyVersion[1:]) // removes 'v'
		}
		if runtime.GOARCH == "arm64" {
			return fmt.Sprintf("trivy_%s_Linux-ARM64.tar.gz", trivyVersion[1:])
		}
	case "darwin":
		if runtime.GOARCH == "amd64" {
			return fmt.Sprintf("trivy_%s_macOS-64bit.tar.gz", trivyVersion[1:])
		}
		if runtime.GOARCH == "arm64" {
			return fmt.Sprintf("trivy_%s_macOS-ARM64.tar.gz", trivyVersion[1:])
		}
	}
	return ""
}
