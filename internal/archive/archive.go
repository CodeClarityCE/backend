// Package archive packs a project directory for upload.
package archive

import (
	"archive/zip"
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// skipped directories hold no source the analysis reads: VCS data and installed packages.
var skipped = map[string]bool{".git": true, "node_modules": true, "vendor": true}

// Zip packs the regular files under dir into a zip archive, paths relative to dir.
// Symbolic links are left out, so nothing outside dir is uploaded.
func Zip(dir string) ([]byte, error) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != dir && skipped[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		return add(w, path, filepath.ToSlash(rel))
	})
	if err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func add(w *zip.Writer, path, name string) error {
	f, err := os.Open(path) //nolint:gosec // a file under the directory the user asked to upload
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	dst, err := w.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate})
	if err != nil {
		return err
	}
	_, err = io.Copy(dst, f)
	return err
}
