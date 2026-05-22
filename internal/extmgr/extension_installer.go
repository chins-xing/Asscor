package extmgr

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/argus-security/argus/internal/logger"
)

type DownloadStrategy interface {
	Fetch(spec ExtensionSpec, dest string) (string, error)
}

type httpDownloader struct {
	client  *http.Client
	timeout time.Duration
}

func newHTTPDownloader(timeout time.Duration) *httpDownloader {
	return &httpDownloader{
		client:  &http.Client{Timeout: timeout},
		timeout: timeout,
	}
}

func (d *httpDownloader) Fetch(spec ExtensionSpec, dest string) (string, error) {
	req, err := http.NewRequest("GET", spec.Source.URL, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("download %s: %w", spec.Source.URL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s: HTTP %d", spec.Source.URL, resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024*1024))
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	if err := spec.VerifyIntegrity(data); err != nil {
		return "", fmt.Errorf("integrity check failed for %s: %w", spec.ID, err)
	}

	ext := filepath.Ext(spec.Source.URL)
	tmpFile := filepath.Join(dest, spec.ID+ext)
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return "", fmt.Errorf("write temp file: %w", err)
	}

	return tmpFile, nil
}

type gitDownloader struct {
	cloneDir string
}

func newGitDownloader(cloneDir string) *gitDownloader {
	return &gitDownloader{cloneDir: cloneDir}
}

func (d *gitDownloader) Fetch(spec ExtensionSpec, dest string) (string, error) {
	cloneTarget := filepath.Join(dest, spec.ID+"_repo")

	if err := os.RemoveAll(cloneTarget); err != nil {
		return "", fmt.Errorf("clean clone target: %w", err)
	}

	args := []string{"clone", "--depth", "1"}
	if spec.Source.Branch != "" {
		args = append(args, "--branch", spec.Source.Branch)
	}
	args = append(args, spec.Source.URL, cloneTarget)

	var stdout, stderr bytes.Buffer
	cmd := exec.Command("git", args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git clone %s: %w\nstderr: %s", spec.Source.URL, err, stderr.String())
	}

	logger.WithComponent("extmgr").Info("cloned extension", "extension_id", spec.ID, "source", spec.Source.URL)
	return cloneTarget, nil
}

type localDownloader struct{}

func newLocalDownloader() *localDownloader {
	return &localDownloader{}
}

func (d *localDownloader) Fetch(spec ExtensionSpec, dest string) (string, error) {
	srcPath := spec.Source.URL
	if !filepath.IsAbs(srcPath) {
		abs, err := filepath.Abs(srcPath)
		if err != nil {
			return "", fmt.Errorf("resolve path %s: %w", srcPath, err)
		}
		srcPath = abs
	}

	info, err := os.Stat(srcPath)
	if err != nil {
		return "", fmt.Errorf("source not found %s: %w", srcPath, err)
	}

	if info.IsDir() {
		return srcPath, nil
	}

	data, err := os.ReadFile(srcPath)
	if err != nil {
		return "", fmt.Errorf("read local file: %w", err)
	}

	if err := spec.VerifyIntegrity(data); err != nil {
		return "", fmt.Errorf("integrity check: %w", err)
	}

	destFile := filepath.Join(dest, spec.ID+filepath.Ext(srcPath))
	if err := os.WriteFile(destFile, data, 0644); err != nil {
		return "", fmt.Errorf("copy local file: %w", err)
	}

	return destFile, nil
}

type ExtensionInstaller struct {
	httpDownloader *httpDownloader
	gitDownloader  *gitDownloader
	localDownloader *localDownloader
	extensionsDir  string
	tmpDir         string
}

func NewExtensionInstaller(extensionsDir string) *ExtensionInstaller {
	tmpDir := filepath.Join(os.TempDir(), "argus-extensions")
	os.MkdirAll(tmpDir, 0755)

	return &ExtensionInstaller{
		httpDownloader:  newHTTPDownloader(120 * time.Second),
		gitDownloader:   newGitDownloader(extensionsDir),
		localDownloader: newLocalDownloader(),
		extensionsDir:   extensionsDir,
		tmpDir:          tmpDir,
	}
}

func (i *ExtensionInstaller) SetHTTPTimeout(d time.Duration) {
	i.httpDownloader.timeout = d
	i.httpDownloader.client.Timeout = d
}

func (i *ExtensionInstaller) getDownloader(sourceType string) (DownloadStrategy, error) {
	switch sourceType {
	case "http", "https":
		return i.httpDownloader, nil
	case "git":
		return i.gitDownloader, nil
	case "local":
		return i.localDownloader, nil
	default:
		return nil, fmt.Errorf("unsupported source type: %s", sourceType)
	}
}

func (i *ExtensionInstaller) Prepare(spec ExtensionSpec) error {
	if err := spec.Validate(); err != nil {
		return fmt.Errorf("validate spec: %w", err)
	}

	if spec.Source.Type == "" {
		spec.Source.Type = detectSourceType(spec.Source.URL)
	}

	installDir := i.getInstallDir(spec)
	if _, err := os.Stat(installDir); err == nil {
		return fmt.Errorf("extension %s is already installed at %s", spec.ID, installDir)
	}

	return nil
}

func (i *ExtensionInstaller) Install(spec ExtensionSpec) (string, error) {
	if err := i.Prepare(spec); err != nil {
		return "", err
	}

	downloader, err := i.getDownloader(spec.Source.Type)
	if err != nil {
		return "", err
	}

	fetchedPath, err := downloader.Fetch(spec, i.tmpDir)
	if err != nil {
		return "", fmt.Errorf("fetch extension %s: %w", spec.ID, err)
	}

	installDir := i.getInstallDir(spec)
	if err := os.MkdirAll(installDir, 0755); err != nil {
		return "", fmt.Errorf("create install dir: %w", err)
	}

	if err := i.extractTo(fetchedPath, installDir); err != nil {
		os.RemoveAll(installDir)
		return "", fmt.Errorf("extract extension %s: %w", spec.ID, err)
	}

	spec.InstallPath = installDir
	spec.InstallTime = time.Now()
	spec.State = ExtStateInstalled

	logger.WithComponent("extmgr").Info("installed extension", "extension_id", spec.ID, "version", spec.Version, "dir", installDir)
	return installDir, nil
}

func (i *ExtensionInstaller) getInstallDir(spec ExtensionSpec) string {
	return filepath.Join(i.extensionsDir, spec.ID+"-"+strings.ReplaceAll(spec.Version, "/", "_"))
}

func (i *ExtensionInstaller) extractTo(srcPath string, destDir string) error {
	ext := strings.ToLower(filepath.Ext(srcPath))

	switch ext {
	case ".zip":
		return i.extractZip(srcPath, destDir)
	case ".gz", ".tgz":
		return i.extractTarGz(srcPath, destDir)
	case ".tar":
		return i.extractTar(srcPath, destDir)
	default:
		if info, err := os.Stat(srcPath); err == nil && info.IsDir() {
			return i.copyDir(srcPath, destDir)
		}
		return i.copyFile(srcPath, filepath.Join(destDir, filepath.Base(srcPath)))
	}
}

func (i *ExtensionInstaller) extractZip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		targetPath := filepath.Join(dest, f.Name)
		if !strings.HasPrefix(filepath.Clean(targetPath), filepath.Clean(dest)+string(os.PathSeparator)) {
			continue
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(targetPath, 0755)
			continue
		}

		os.MkdirAll(filepath.Dir(targetPath), 0755)

		rc, err := f.Open()
		if err != nil {
			return err
		}

		outFile, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			rc.Close()
			return err
		}

		_, err = io.Copy(outFile, rc)
		rc.Close()
		outFile.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func (i *ExtensionInstaller) extractTarGz(src, dest string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gzr.Close()

	return i.extractTarReader(tar.NewReader(gzr), dest)
}

func (i *ExtensionInstaller) extractTar(src, dest string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	return i.extractTarReader(tar.NewReader(f), dest)
}

func (i *ExtensionInstaller) extractTarReader(tr *tar.Reader, dest string) error {
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		targetPath := filepath.Join(dest, header.Name)
		if !strings.HasPrefix(filepath.Clean(targetPath), filepath.Clean(dest)+string(os.PathSeparator)) {
			continue
		}

		switch header.Typeflag {
		case tar.TypeDir:
			os.MkdirAll(targetPath, 0755)
		case tar.TypeReg:
			os.MkdirAll(filepath.Dir(targetPath), 0755)
			outFile, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			_, err = io.Copy(outFile, tr)
			outFile.Close()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (i *ExtensionInstaller) copyDir(src, dest string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relPath, _ := filepath.Rel(src, path)
		targetPath := filepath.Join(dest, relPath)

		if info.IsDir() {
			return os.MkdirAll(targetPath, 0755)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		os.MkdirAll(filepath.Dir(targetPath), 0755)
		return os.WriteFile(targetPath, data, info.Mode())
	})
}

func (i *ExtensionInstaller) copyFile(src, dest string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	os.MkdirAll(filepath.Dir(dest), 0755)
	return os.WriteFile(dest, data, 0644)
}
