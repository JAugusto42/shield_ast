package scanners

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/JAugusto42/shield-ast/internal/downloader"
)

const opengrepVersion = "v1.25.0"

// SetupOpengrep dynamically downloads the correct Opengrep binary for the host OS.
func SetupOpengrep(cacheDir string) (string, error) {
	fileName := getOpengrepFileName()
	if fileName == "" {
		return "", fmt.Errorf("unsupported OS or Architecture for Opengrep: %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	destPath := filepath.Join(cacheDir, "opengrep")
	if runtime.GOOS == "windows" {
		destPath += ".exe"
	}

	// [NEW] Cache Verification
	if downloader.IsCached(destPath) {
		if os.Getenv("SHIELD_DEBUG") == "true" {
			log.Printf("[DEBUG] Opengrep found in cache: %s", destPath)
		}
		return destPath, nil
	}

	url := fmt.Sprintf("https://github.com/opengrep/opengrep/releases/download/%s/%s", opengrepVersion, fileName)

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

func getOpengrepFileName() string {
	switch runtime.GOOS {
	case "linux":
		if runtime.GOARCH == "amd64" {
			return "opengrep_manylinux_x86"
		}
		if runtime.GOARCH == "arm64" {
			return "opengrep_manylinux_aarch64"
		}
	case "darwin":
		if runtime.GOARCH == "amd64" {
			return "opengrep_osx_x86"
		}
		if runtime.GOARCH == "arm64" {
			return "opengrep_osx_arm64"
		}
	case "windows":
		if runtime.GOARCH == "amd64" {
			return "opengrep_windows_x86.exe"
		}
	}
	return ""
}
