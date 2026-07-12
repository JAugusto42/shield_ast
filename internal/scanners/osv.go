package scanners

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/JAugusto42/shield-ast/internal/downloader"
)

const osvVersion = "v2.4.0"

// SetupOSV resolves the URL, downloads the binary and sets execution permissions
func SetupOSV(cacheDir string) (string, error) {
	fileName := getOSVFileName()
	if fileName == "" {
		return "", fmt.Errorf("unsupported OS or Architecture for OSV: %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	destPath := filepath.Join(cacheDir, "osv-scanner")
	if runtime.GOOS == "windows" {
		destPath += ".exe"
	}

	// Verify if the binary is already downloaded
	if downloader.IsCached(destPath) {
		if os.Getenv("SHIELD_DEBUG") == "true" {
			log.Printf("[DEBUG] OSV-Scanner found in cache: %s", destPath)
		}
		return destPath, nil
	}

	url := fmt.Sprintf("https://github.com/google/osv-scanner/releases/download/%s/%s", osvVersion, fileName)

	err := downloader.DownloadFile(url, destPath)
	if err != nil {
		return "", err
	}

	if runtime.GOOS != "windows" {
		if err := downloader.MakeExecutable(destPath); err != nil {
			return "", err
		}
	}

	return destPath, nil
}

func getOSVFileName() string {
	switch runtime.GOOS {
	case "linux":
		if runtime.GOARCH == "amd64" {
			return "osv-scanner_linux_amd64"
		}
		if runtime.GOARCH == "arm64" {
			return "osv-scanner_linux_arm64"
		}
	case "darwin":
		if runtime.GOARCH == "amd64" {
			return "osv-scanner_darwin_amd64"
		}
		if runtime.GOARCH == "arm64" {
			return "osv-scanner_darwin_arm64"
		}
	case "windows":
		if runtime.GOARCH == "amd64" {
			return "osv-scanner_windows_amd64.exe"
		}
		if runtime.GOARCH == "arm64" {
			return "osv-scanner_windows_arm64.exe"
		}
	}
	return ""
}
