package app

import (
	"crypto/md5"
	"encoding/hex"
	"path/filepath"
)

// mihomoHashedProviderCachePath mirrors Mihomo's GetPathByHash layout for an
// HTTP provider whose optional path is omitted. MD5 is part of that on-disk
// compatibility contract; it is not used for authentication or integrity.
func mihomoHashedProviderCachePath(root, directory, sourceURL string) string {
	//nolint:gosec // Compatibility with Mihomo's cache filename algorithm.
	digest := md5.Sum([]byte(sourceURL))
	return filepath.Join(root, directory, hex.EncodeToString(digest[:]))
}
