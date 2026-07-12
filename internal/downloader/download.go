package downloader

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
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
	// Timeout aumentado para 15 minutos
	client := http.Client{Timeout: 15 * time.Minute}

	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP status %d", resp.StatusCode)
	}

	// 1. Cria um arquivo temporário exclusivo para o download em andamento
	tmpPath := destPath + ".downloading"
	out, err := os.Create(tmpPath)
	if err != nil {
		return err
	}

	// 2. Copia os bytes da internet para o arquivo temporário
	_, err = io.Copy(out, resp.Body)

	// Feche o arquivo ANTES de tentar renomear ou deletar
	out.Close()

	if err != nil {
		// Se o download falhar no meio (ex: a internet caiu), limpa o lixo
		os.Remove(tmpPath)
		return err
	}

	// 3. Download atômico: Renomeia do temporário para o arquivo oficial
	// Isso garante que o IsCached() nunca seja enganado por um arquivo pela metade
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
