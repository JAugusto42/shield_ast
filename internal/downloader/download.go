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

func DownloadAndExtractTarGz(url, destPath, targetBinary string) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download: HTTP %d", resp.StatusCode)
	}

	// Cria o leitor de GZIP
	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzr.Close()

	// Cria o leitor de TAR
	tr := tar.NewReader(gzr)

	// Itera sobre os arquivos dentro do .tar.gz
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break // Fim do arquivo
		}
		if err != nil {
			return fmt.Errorf("error reading tar archive: %w", err)
		}

		// Verifica se o arquivo atual do loop é o binário que queremos
		if header.Typeflag == tar.TypeReg && filepath.Base(header.Name) == targetBinary {
			// Cria o arquivo de destino com permissão de execução (0755)
			outFile, err := os.OpenFile(destPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0755)
			if err != nil {
				return fmt.Errorf("failed to create executable file: %w", err)
			}
			defer outFile.Close()

			// Copia o conteúdo do tar para o arquivo físico
			if _, err := io.Copy(outFile, tr); err != nil {
				return fmt.Errorf("failed to extract binary: %w", err)
			}

			// Binário encontrado e extraído com sucesso
			return nil
		}
	}

	return fmt.Errorf("binary '%s' not found in the archive", targetBinary)
}
