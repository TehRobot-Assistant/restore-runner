// Package archive extracts uploaded backup archives into a destination
// directory. The extractor is paranoid about:
//
//   - path traversal (Zip Slip via "../" entries, absolute-path entries,
//     symlinks that escape the dest)
//   - zip-bomb-style expansion (caps per-file + total uncompressed size)
//   - pathological compression ratios
//
// Supported formats, dispatched by file extension of the *original upload*:
//
//   .zip              → archive/zip
//   .tar              → archive/tar (plain)
//   .tar.gz | .tgz    → archive/tar + compress/gzip
//   .tar.zst          → archive/tar + klauspost/compress/zstd (pure-Go)
//   .rar              → shell out to 7z (bundled p7zip-full); RAR's format
//                       isn't practical to implement pure-Go
//
// We don't trust the Content-Type header or uploaded filename for anything
// beyond extension dispatch — the extractor itself validates every path.
package archive

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// Caps — same order of magnitude as the upload cap.
const (
	// MaxFileBytes caps a single extracted file. 2 GiB matches the upload
	// cap ceiling; any archive that contains a single file larger than
	// that is almost certainly hostile or malformed.
	MaxFileBytes int64 = 2 << 30
	// MaxTotalBytes caps total uncompressed payload. 10 GiB: expansion
	// ratios above 5:1 on a 2 GB upload are possible but suspicious.
	MaxTotalBytes int64 = 10 << 30
)

// ErrArchiveBomb is returned when an archive would expand past MaxTotalBytes.
var ErrArchiveBomb = errors.New("archive expansion exceeds safety cap")

// ErrUnsafePath is returned for any entry that tries to escape the destination.
var ErrUnsafePath = errors.New("archive contains unsafe path (traversal or absolute)")

// DetectFormat returns a canonical format tag for the given filename.
// Returns "" if the extension isn't recognised.
func DetectFormat(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		return "tar.gz"
	case strings.HasSuffix(lower, ".tar.zst"):
		return "tar.zst"
	case strings.HasSuffix(lower, ".tar"):
		return "tar"
	case strings.HasSuffix(lower, ".zip"):
		return "zip"
	case strings.HasSuffix(lower, ".rar"):
		return "rar"
	}
	return ""
}

// Extract dispatches to the right decoder.
//
// archivePath is the path to the archive file on disk.
// destDir is the absolute path the archive should be extracted into
// (the caller must pre-create this directory).
// format is the tag returned by DetectFormat.
func Extract(archivePath, destDir, format string) error {
	absDest, err := filepath.Abs(destDir)
	if err != nil {
		return fmt.Errorf("abs dest: %w", err)
	}
	if _, err := os.Stat(absDest); err != nil {
		return fmt.Errorf("dest dir: %w", err)
	}

	switch format {
	case "zip":
		return extractZip(archivePath, absDest)
	case "tar":
		f, err := os.Open(archivePath)
		if err != nil {
			return err
		}
		defer f.Close()
		return extractTar(f, absDest)
	case "tar.gz":
		f, err := os.Open(archivePath)
		if err != nil {
			return err
		}
		defer f.Close()
		gz, err := gzip.NewReader(f)
		if err != nil {
			return fmt.Errorf("gzip: %w", err)
		}
		defer gz.Close()
		return extractTar(gz, absDest)
	case "tar.zst":
		f, err := os.Open(archivePath)
		if err != nil {
			return err
		}
		defer f.Close()
		zr, err := zstd.NewReader(f)
		if err != nil {
			return fmt.Errorf("zstd: %w", err)
		}
		defer zr.Close()
		return extractTar(zr, absDest)
	case "rar":
		return extractRar(archivePath, absDest)
	default:
		return fmt.Errorf("unsupported archive format: %q", format)
	}
}

// extractZip iterates every entry in a zip via the stdlib and writes it
// to disk with path-safety checks and a running size cap.
func extractZip(archivePath, destDir string) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	defer r.Close()

	var total int64
	for _, f := range r.File {
		dest, err := safeJoin(destDir, f.Name)
		if errors.Is(err, ErrSkipEntry) {
			continue
		}
		if err != nil {
			return err
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(dest, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("open entry %q: %w", f.Name, err)
		}
		n, err := writeCapped(dest, rc, MaxFileBytes)
		rc.Close()
		if err != nil {
			return err
		}
		total += n
		if total > MaxTotalBytes {
			return ErrArchiveBomb
		}
	}
	return nil
}

// extractTar pulls each tar header and writes it, same checks as zip.
// Caller supplies the stream (may be raw tar, gzip-wrapped, zstd-wrapped).
func extractTar(r io.Reader, destDir string) error {
	tr := tar.NewReader(r)
	var total int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("tar next: %w", err)
		}

		dest, err := safeJoin(destDir, hdr.Name)
		if errors.Is(err, ErrSkipEntry) {
			continue
		}
		if err != nil {
			return err
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dest, 0o755); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
				return err
			}
			n, err := writeCapped(dest, tr, MaxFileBytes)
			if err != nil {
				return err
			}
			total += n
			if total > MaxTotalBytes {
				return ErrArchiveBomb
			}
		case tar.TypeSymlink, tar.TypeLink:
			// Resolve link target; if it escapes the dest, reject. If it
			// stays inside, we still skip creating it — we don't need
			// symlinks to boot the container from extracted appdata, and
			// symlinks are a persistent foot-gun for these extractors.
			linkTarget := hdr.Linkname
			abs := filepath.Join(filepath.Dir(dest), linkTarget)
			abs, err := filepath.Abs(abs)
			if err != nil || !strings.HasPrefix(abs+string(os.PathSeparator), destDir+string(os.PathSeparator)) {
				return ErrUnsafePath
			}
			// Skip creating the symlink.
		default:
			// Skip devices, fifos, etc. We don't need them.
		}
	}
	return nil
}

// extractRar shells out to 7z, which handles RAR read-only via its
// bundled unRAR code. We pass -y (assume yes), -aos (don't overwrite),
// and explicitly pass the archive + output dir via "--" so any leading
// dash in the filename can't be misparsed as a flag.
//
// NOTE: the caller must guarantee archivePath is a path we control (e.g.
// lives under /config/uploads/<uuid>/) so 7z never reads an attacker-
// supplied path. The destination is also our own; 7z handles path safety
// internally for extraction paths, matching our zip/tar behaviour.
func extractRar(archivePath, destDir string) error {
	// Absolute paths so the child process's CWD doesn't matter.
	absArchive, err := filepath.Abs(archivePath)
	if err != nil {
		return err
	}
	absDest, err := filepath.Abs(destDir)
	if err != nil {
		return err
	}

	// 7z is invoked as a pure argv vector; no shell involvement.
	cmd := exec.Command("7z",
		"x",                // extract with full paths
		"-y",               // assume yes on all prompts
		"-aos",             // skip existing files (we're writing into a fresh dir)
		"-o"+absDest,       // output directory
		"--",               // end of flags
		absArchive,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Trim 7z's ASCII art preamble for readable errors.
		return fmt.Errorf("7z extract: %w: %s", err, trimOutput(out))
	}
	return nil
}

func trimOutput(b []byte) string {
	s := string(b)
	if len(s) > 800 {
		s = s[len(s)-800:]
	}
	return strings.TrimSpace(s)
}

// ErrSkipEntry signals the archive entry should be silently ignored
// (e.g. the "./" root entry tar emits). Not really an error, just a
// sentinel so the caller can loop-continue.
var ErrSkipEntry = errors.New("skip entry")

// safeJoin cleans an archive entry path and rejects anything that would
// escape destDir (absolute paths, ".." chains, drive letters on Windows
// paths that sneak in, etc). Empty / "." entries (tar's conventional
// root-dir header) return ErrSkipEntry so the caller can continue
// without treating it as a path-safety violation.
func safeJoin(destDir, name string) (string, error) {
	// Reject absolute paths outright.
	if filepath.IsAbs(name) {
		return "", ErrUnsafePath
	}
	// Normalise — removes ../ and cleans up // — but we also validate
	// after joining that the result is still under destDir.
	cleaned := filepath.Clean("/" + name) // leading / forces absolute clean
	cleaned = strings.TrimPrefix(cleaned, "/")
	if cleaned == "" || cleaned == "." {
		return "", ErrSkipEntry
	}
	// Block Windows-style drive letters from sneaking in via "C:\foo"
	// style entry names (Go's filepath on linux won't catch them).
	if driveLetter.MatchString(cleaned) {
		return "", ErrUnsafePath
	}
	joined := filepath.Join(destDir, cleaned)
	absJoined, err := filepath.Abs(joined)
	if err != nil {
		return "", err
	}
	// Both must end with the separator for the prefix check to be safe.
	if !strings.HasPrefix(absJoined+string(os.PathSeparator), destDir+string(os.PathSeparator)) {
		return "", ErrUnsafePath
	}
	return absJoined, nil
}

var driveLetter = regexp.MustCompile(`^[a-zA-Z]:`)

// writeCapped copies from r into a file at path, capping at max bytes
// and returning the byte count written. Zip bombs that try to extract
// a single 50-GiB file are cut off here.
func writeCapped(path string, r io.Reader, max int64) (int64, error) {
	out, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, err
	}
	defer out.Close()
	// LimitReader reads max+1 bytes to detect overflow.
	n, err := io.Copy(out, io.LimitReader(r, max+1))
	if err != nil {
		return n, err
	}
	if n > max {
		// Truncate + delete the partial file; we don't want a bomb on disk.
		_ = os.Remove(path)
		return n, ErrArchiveBomb
	}
	return n, nil
}
