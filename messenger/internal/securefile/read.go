// Package securefile reads operator-pinned inputs without following a path
// substitution between validation and use.
package securefile

import (
	"errors"
	"io"
	"os"
)

// ReadBoundedRegular opens path once, proves the opened object is the regular
// file observed at the path, and reads no more than limit bytes. A symlink or
// replacement between Lstat and Open fails the SameFile comparison instead of
// redirecting a privileged daemon to another input.
func ReadBoundedRegular(path string, limit int64) ([]byte, error) {
	raw, _, err := ReadBoundedRegularInfo(path, limit)
	return raw, err
}

// ReadBoundedRegularInfo is ReadBoundedRegular that also returns the
// FileInfo of the opened file, so a caller can check the owner and mode of
// exactly what it read rather than of a path that may since have changed.
func ReadBoundedRegularInfo(path string, limit int64) ([]byte, os.FileInfo, error) {
	if path == "" || limit < 1 {
		return nil, nil, errors.New("invalid bounded file request")
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, nil, errors.New("inspect bounded file")
	}
	if !pathInfo.Mode().IsRegular() || pathInfo.Size() <= 0 || pathInfo.Size() > limit {
		return nil, nil, errors.New("bounded file must be a non-empty regular file within its limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, errors.New("open bounded file")
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openedInfo) {
		return nil, nil, errors.New("bounded file changed while it was opened")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, nil, errors.New("read bounded file")
	}
	if len(raw) == 0 || int64(len(raw)) > limit {
		return nil, nil, errors.New("bounded file is empty or exceeds its limit")
	}
	return raw, openedInfo, nil
}
