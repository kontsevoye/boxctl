package ruleconvert

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
)

// Binaries are trusted, installed native executables, never URLs or shell text.
// The target binary is overridden by a staged core during update preflight.
type Binaries struct {
	SingBox string `json:"singBox"`
	Mihomo  string `json:"mihomo"`
}
type Codec struct{ Binaries Binaries }
type Artifact struct {
	Data             []byte
	Format, Behavior string
	Count            int
}

func (c Codec) Convert(ctx context.Context, data []byte, target, hint string) (Artifact, error) {
	if len(data) == 0 || len(data) > MaxBytes {
		return Artifact{}, errors.New("empty or oversized source rule set")
	}
	root, err := os.MkdirTemp("", "boxctl-rule-codec-")
	if err != nil {
		return Artifact{}, err
	}
	defer os.RemoveAll(root)
	var rules []predicate
	trimmed := bytes.TrimSpace(data)
	if bytes.HasPrefix(trimmed, []byte("//")) || bytes.HasPrefix(trimmed, []byte("/*")) || bytes.HasPrefix(trimmed, []byte("{")) {
		if cleaned, e := cleanJSON(data); e == nil {
			data = cleaned
			trimmed = bytes.TrimSpace(data)
		}
	}
	var header map[string]json.RawMessage
	isJSON := json.Unmarshal(trimmed, &header) == nil && header["rules"] != nil
	if target == "sing-box" && isJSON {
		doc, e := nativeSingSource(data)
		if e != nil {
			return Artifact{}, e
		}
		result, e := c.command(ctx, root, c.Binaries.SingBox, data, []string{"rule-set", "compile", "-o", "OUTPUT", "INPUT"})
		return Artifact{Data: result, Format: "binary", Count: len(doc.Rules)}, e
	}
	switch {
	case bytes.HasPrefix(data, []byte("SRS")):
		decoded, e := c.command(ctx, root, c.Binaries.SingBox, data, []string{"rule-set", "decompile", "-o", "OUTPUT", "INPUT"})
		if e != nil {
			return Artifact{}, fmt.Errorf("decode SRS: %w", e)
		}
		if target == "sing-box" {
			// Preserve native-only predicates when the source and target are the
			// same engine; only cross-engine conversion needs the common IR.
			return c.Convert(ctx, decoded, target, hint)
		}
		rules, err = parseSing(decoded)
	case bytes.HasPrefix(data, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		behavior, e := mrsBehavior(data)
		if e != nil {
			return Artifact{}, e
		}
		decoded, e := c.command(ctx, root, c.Binaries.Mihomo, data, []string{"convert-ruleset", behavior, "mrs", "INPUT", "OUTPUT"})
		if e != nil {
			return Artifact{}, fmt.Errorf("decode MRS: %w", e)
		}
		rules, err = parseText(decoded, behavior)
	case isJSON:
		rules, err = parseSing(data)
	default:
		rules, err = parseText(data, hint)
	}
	if err != nil {
		return Artifact{}, err
	}
	artifact := Artifact{Count: len(rules)}
	switch target {
	case "sing-box":
		var source []byte
		source, err = encodeSing(rules)
		if err != nil {
			return artifact, err
		}
		artifact.Data, err = c.command(ctx, root, c.Binaries.SingBox, source, []string{"rule-set", "compile", "-o", "OUTPUT", "INPUT"})
		artifact.Format = "binary"
	case "mihomo":
		artifact.Behavior = outputBehavior(rules)
		var source []byte
		source, err = mihomoText(rules, artifact.Behavior)
		if err != nil {
			return artifact, err
		}
		if artifact.Behavior == "classical" {
			artifact.Data = source
			artifact.Format = "text"
		} else {
			artifact.Data, err = c.command(ctx, root, c.Binaries.Mihomo, source, []string{"convert-ruleset", artifact.Behavior, "text", "INPUT", "OUTPUT"})
			artifact.Format = "mrs"
		}
	default:
		return artifact, errors.New("unknown conversion target")
	}
	return artifact, err
}
func mrsBehavior(data []byte) (string, error) {
	reader, err := zstd.NewReader(bytes.NewReader(data), zstd.WithDecoderMaxMemory(MaxBytes), zstd.WithDecoderConcurrency(1))
	if err != nil {
		return "", errors.New("invalid MRS compression")
	}
	defer reader.Close()
	var header [5]byte
	if _, err = io.ReadFull(reader, header[:]); err != nil || !bytes.Equal(header[:4], []byte{'M', 'R', 'S', 1}) {
		return "", errors.New("invalid or unsupported MRS header")
	}
	switch header[4] {
	case 0:
		return "domain", nil
	case 1:
		return "ipcidr", nil
	default:
		return "", errors.New("unsupported MRS behavior")
	}
}
func (c Codec) command(ctx context.Context, root, binary string, data []byte, args []string) ([]byte, error) {
	if !filepath.IsAbs(binary) {
		return nil, errors.New("required native codec is not installed; install both cores in Settings")
	}
	info, err := os.Stat(binary)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
		return nil, errors.New("required native codec executable is unavailable")
	}
	input, output := filepath.Join(root, "input"), filepath.Join(root, "output")
	if err = os.WriteFile(input, data, 0o600); err != nil {
		return nil, err
	}
	if err = os.WriteFile(output, nil, 0o600); err != nil {
		return nil, err
	}
	for i, v := range args {
		switch v {
		case "INPUT":
			args[i] = input
		case "OUTPUT":
			args[i] = output
		}
	}
	operation, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	//nolint:gosec // Trusted installed native executable; fixed arguments, no shell.
	cmd := exec.CommandContext(operation, binary, args...)
	cmd.WaitDelay = time.Second
	// Core diagnostics may include rule values. Keep public failures bounded and
	// independent of upstream URLs, headers and user data.
	var diagnostics boundedOutput
	cmd.Stdout = &diagnostics
	cmd.Stderr = &diagnostics
	if err = cmd.Run(); err != nil {
		if operation.Err() != nil {
			return nil, operation.Err()
		}
		if strings.Contains(diagnostics.String(), "AdGuard") {
			return nil, errors.New("compiled AdGuard rules cannot be decompiled losslessly by sing-box")
		}
		return nil, errors.New("native rule codec rejected the input")
	}
	return readRegular(output, MaxBytes)
}

type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if b.Len() < 8192 {
		_, _ = b.Buffer.Write(p[:min(n, 8192-b.Len())])
	}
	return n, nil
}
func readRegular(path string, limit int64) ([]byte, error) {
	//nolint:gosec // Explicit administrator-selected initial file or manager-owned cache; bounded regular file and identity checks follow.
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("expected bounded regular file")
	}
	//nolint:gosec // Manager-owned path or explicitly selected initial file; identity checked below.
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, opened) {
		return nil, errors.New("file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if int64(len(data)) > limit {
		return nil, errors.New("file exceeds size limit")
	}
	return data, err
}
