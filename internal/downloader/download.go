package downloader

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func isDebug() bool {
	return os.Getenv("SHIELD_DEBUG") == "true"
}

// DownloadFile fetches a file from the given URL and saves it to destPath with retry logic.
func DownloadFile(url, destPath string) error {
	const maxRetries = 3
	var err error

	if isDebug() {
		log.Printf("[DEBUG] Starting download from: %s", url)
	}

	for i := 1; i <= maxRetries; i++ {
		err = tryDownload(url, destPath)
		if err == nil {
			if isDebug() {
				log.Printf("[DEBUG] Successfully downloaded to: %s", destPath)
			}
			return nil // Success
		}

		if isDebug() {
			log.Printf("[DEBUG] Failed to download %s (Attempt %d/%d): %v", url, i, maxRetries, err)
		}

		if i < maxRetries {
			time.Sleep(time.Duration(i*2) * time.Second) // Simple exponential backoff
		}
	}

	return fmt.Errorf("failed to download after %d attempts: %v", maxRetries, err)
}

func tryDownload(url, destPath string) error {
	// create client with a timeout to avoid hanging indefinitely
	client := http.Client{Timeout: 15 * time.Minute}

	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP status %d", resp.StatusCode)
	}

	// Create a temporary file to download the content
	// This ensures that if the download is interrupted, we don't leave a half-written file at destPath.
	// The temporary file will be renamed to destPath only after a successful download.
	tmpPath := destPath + ".downloading"
	out, err := os.Create(tmpPath)
	if err != nil {
		return err
	}

	_, err = io.Copy(out, resp.Body)

	out.Close()

	if err != nil {
		// if the download fails, remove the temporary file to avoid leaving a corrupted file
		os.Remove(tmpPath)
		return err
	}

	// Atomically rename the temporary file to the final destination path
	// This ensures that the file at destPath is either the old version or the new version, but never a half-written file.
	return os.Rename(tmpPath, destPath)
}

// MakeExecutable applies chmod +x (0755) to the given file path
func MakeExecutable(path string) error {
	if isDebug() {
		log.Printf("[DEBUG] Setting executable permissions for: %s", path)
	}
	return os.Chmod(path, 0755)
}

// IsCached checks if the binary already exists at the given path
func IsCached(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	// Make sure it's a file and not a directory
	return !info.IsDir()
}

func DownloadAndExtractTarGz(url, destPath, targetBinary string) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download: HTTP %d", resp.StatusCode)
	}

	// gzip reader to decompress the .tar.gz file
	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzr.Close()

	// create a tar reader from the gzip reader
	tr := tar.NewReader(gzr)

	// interate through the files in the tar archive
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break // break when we reach the end of the archive
		}
		if err != nil {
			return fmt.Errorf("error reading tar archive: %w", err)
		}

		// Verify if the current file is the target binary
		if header.Typeflag == tar.TypeReg && filepath.Base(header.Name) == targetBinary {
			// Create the destination file with execute permissions (0755)
			outFile, err := os.OpenFile(destPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0755)
			if err != nil {
				return fmt.Errorf("failed to create executable file: %w", err)
			}
			defer outFile.Close()

			// Copy the content of the tar to the physical file
			if _, err := io.Copy(outFile, tr); err != nil {
				return fmt.Errorf("failed to extract binary: %w", err)
			}

			// all done!
			return nil
		}
	}

	return fmt.Errorf("binary '%s' not found in the archive", targetBinary)
}
