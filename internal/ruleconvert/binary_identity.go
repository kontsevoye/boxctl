package ruleconvert

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync"
)

var identities sync.Map

func binaryIdentity(binaries Binaries) string {
	hash := sha256.New()
	for _, path := range []string{binaries.SingBox, binaries.Mihomo} {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			_, _ = io.WriteString(hash, path+":unavailable\n")
			continue
		}
		key := fmt.Sprintf("%s:%d:%d", path, info.Size(), info.ModTime().UnixNano())
		if cached, ok := identities.Load(key); ok {
			_, _ = io.WriteString(hash, cached.(string))
			continue
		}
		//nolint:gosec // Trusted installed core path, only hashed to bind the cache to its exact codec build.
		file, err := os.Open(path)
		if err != nil {
			_, _ = io.WriteString(hash, key)
			continue
		}
		sum := sha256.New()
		_, err = io.Copy(sum, io.LimitReader(file, 256<<20))
		_ = file.Close()
		if err != nil {
			_, _ = io.WriteString(hash, key)
			continue
		}
		value := hex.EncodeToString(sum.Sum(nil))
		identities.Store(key, value)
		_, _ = io.WriteString(hash, value)
	}
	return hex.EncodeToString(hash.Sum(nil))
}
