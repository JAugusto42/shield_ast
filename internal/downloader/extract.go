package downloader

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
)

// ExtractTarGzBinary reads a .tar.gz file, finds a specific binary inside it,
// and extracts only that binary to the destination directory.
func ExtractTarGzBinary(tarGzPath, destDir, targetBinaryName string) (string, error) {
	if isDebug() {
		log.Printf("[DEBUG] Extracting %s from %s", targetBinaryName, tarGzPath)
	}

	// 1. Open the physical file
	file, err := os.Open(tarGzPath)
	if err != nil {
		return "", err
	}
	defer file.Close() // Always defer close immediately after opening

	// 2. Wrap it with a GZIP reader
	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return "", err
	}
	defer gzReader.Close()

	// 3. Wrap the GZIP reader with a TAR reader
	tarReader := tar.NewReader(gzReader)

	// Iterate through the files inside the tar archive
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return "", err
		}

		// We only care about regular files that match our target name
		if header.Typeflag == tar.TypeReg {
			// header.Name could be "trivy" or "folder/trivy", we just want the base name
			if filepath.Base(header.Name) == targetBinaryName {
				outPath := filepath.Join(destDir, targetBinaryName)

				// Create the destination file
				outFile, err := os.Create(outPath)
				if err != nil {
					return "", err
				}

				// Copy bytes from the TAR reader into the new file
				if _, err := io.Copy(outFile, tarReader); err != nil {
					outFile.Close()
					return "", err
				}
				outFile.Close()

				// Success! We found and extracted the binary
				if isDebug() {
					log.Printf("[DEBUG] Extracted binary to: %s", outPath)
				}
				return outPath, nil
			}
		}
	}

	return "", fmt.Errorf("binary %s not found inside archive", targetBinaryName)
}
