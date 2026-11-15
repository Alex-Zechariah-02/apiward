// Reading the configuration file: a regular file, checked before and after
// it is opened, decoded strictly with ${NAME} references resolved from the
// environment, then the files it names (upstream TLS profiles, identity key).

package gateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Alex-Zechariah-02/apiward/internal/forward"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// settingsSource names the configuration file a gateway read and the SHA-256
// of its bytes, for the start record.
type settingsSource struct {
	path   string
	digest string
}

// loadNativeConfig reads and checks the configuration file at path and reads
// the files it names. The controller checks the rest of its own settings, the
// admin address and the trust key, before it opens the database.
func loadNativeConfig(path string) (nativeConfig, error) {
	cfg, err := readNativeConfig(path)
	if err != nil {
		return nativeConfig{}, err
	}
	return cfg, cfg.loadFiles()
}

// readNativeConfig reads and checks the configuration file at path alone,
// without the key and certificate files it names: what the health command
// needs.
func readNativeConfig(path string) (nativeConfig, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nativeConfig{}, err
	}
	data, err := readSettings(path)
	if err != nil {
		return nativeConfig{}, err
	}
	settings, err := decodeNativeFile(data)
	if err != nil {
		return nativeConfig{}, err
	}
	cfg, err := settings.check()
	if err != nil {
		return nativeConfig{}, err
	}
	sum := sha256.Sum256(data)
	cfg.source = settingsSource{path: path, digest: hex.EncodeToString(sum[:])}
	return cfg, nil
}

// readSettings reads the file at path, which must be a regular file: it is
// checked before it is opened, since opening a device or pipe can block, and
// again once open, so a file swapped in between is refused.
func readSettings(path string) ([]byte, error) {
	named, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !named.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file, not a link, device or directory", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(named, opened) {
		return nil, fmt.Errorf("%s was replaced while it was opened", path)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxConfigBytes {
		return nil, fmt.Errorf("the file is larger than %d bytes", maxConfigBytes)
	}
	return data, nil
}

// loadFiles reads the files the settings name beyond the configuration file:
// the upstream TLS profiles and the identity signing key.
func (cfg *nativeConfig) loadFiles() error {
	u := cfg.file.Upstream
	network, err := forward.LoadNetwork(u.AllowPublicAddresses, u.TLSProfiles, cfg.sessionLife)
	if err != nil {
		return err
	}
	cfg.controller.Network = network
	return cfg.identity(u)
}

// decodeNativeFile parses the configuration document. It refuses what
// encoding/json alone would accept ambiguously: repeated or non-lowercase
// member names, unknown members and anything after the document.
func decodeNativeFile(data []byte) (nativeFile, error) {
	// The document's kind and version are read first, so a file written for
	// another gateway or version is reported as such rather than as a set of
	// unknown members.
	decoder := json.NewDecoder(bytes.NewReader(data))
	var header map[string]json.RawMessage
	if err := decoder.Decode(&header); err != nil || header == nil {
		if _, wrongType := errors.AsType[*json.UnmarshalTypeError](err); wrongType || err == nil {
			return nativeFile{}, errors.New("the file is not a JSON object")
		}
		return nativeFile{}, errors.New("the file is not valid JSON")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nativeFile{}, errors.New("the file holds data after the JSON value")
	}
	if _, legacy := header["apps"]; legacy {
		return nativeFile{}, errors.New("this is a Caddy configuration (top-level \"apps\"); write a native configuration instead, it is not converted automatically")
	}
	if err := policy.CheckMembers(data, maxConfigDepth); err != nil {
		policyErr, _ := errors.AsType[*policy.PolicyError](err)
		switch {
		case policyErr != nil && policyErr.Code == "DUPLICATE_MEMBER":
			return nativeFile{}, fmt.Errorf("member %q is repeated in one object", policyErr.Field)
		case policyErr != nil && policyErr.Code == "UNKNOWN_FIELD":
			return nativeFile{}, errors.New("a member name is not made of lower-case letters, digits and underscores")
		case policyErr != nil && policyErr.Code == "LIMIT_EXCEEDED":
			return nativeFile{}, errors.New("the document is nested too deeply")
		}
		return nativeFile{}, errors.New("the file is not valid JSON")
	}
	var version int
	if err := json.Unmarshal(header["version"], &version); err != nil || version != nativeConfigVersion {
		return nativeFile{}, fmt.Errorf("version must be %d, the only configuration version this gateway reads", nativeConfigVersion)
	}
	data, err := resolveReferences(data)
	if err != nil {
		return nativeFile{}, err
	}

	var settings nativeFile
	if err := policy.DecodeStrict(data, &settings); err != nil {
		if typeErr, ok := errors.AsType[*json.UnmarshalTypeError](err); ok {
			return nativeFile{}, fmt.Errorf("%s: a JSON %s is not a valid value", typeErr.Field, typeErr.Value)
		}
		return nativeFile{}, errors.New(strings.TrimPrefix(err.Error(), "json: "))
	}
	return settings, nil
}

// variableName is an environment variable name a reference may use.
var variableName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// resolveReferences replaces every ${NAME} in the document's string values
// with the environment variable NAME, as Docker Compose does; "$${" writes a
// literal "${". An unset variable or a malformed reference is refused, so a
// setting never silently becomes empty. A document without "${" is returned
// unchanged.
func resolveReferences(data []byte) ([]byte, error) {
	if !bytes.Contains(data, []byte("${")) {
		return data, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return nil, errors.New("the file is not valid JSON")
	}
	resolved, err := resolveValue(document, "")
	if err != nil {
		return nil, err
	}
	return json.Marshal(resolved)
}

// resolveValue resolves the references in value, whose setting name is at.
func resolveValue(value any, at string) (any, error) {
	var err error
	switch v := value.(type) {
	case string:
		return resolveString(v, at)
	case map[string]any:
		for name, member := range v {
			if v[name], err = resolveValue(member, strings.TrimPrefix(at+"."+name, ".")); err != nil {
				return nil, err
			}
		}
	case []any:
		for i, member := range v {
			if v[i], err = resolveValue(member, fmt.Sprintf("%s[%d]", at, i)); err != nil {
				return nil, err
			}
		}
	}
	return value, nil
}

// resolveString resolves the references in one string setting.
func resolveString(s, at string) (string, error) {
	var out strings.Builder
	for {
		start := strings.Index(s, "${")
		if start < 0 {
			out.WriteString(s)
			return out.String(), nil
		}
		if start > 0 && s[start-1] == '$' {
			out.WriteString(s[:start-1])
			out.WriteString("${")
			s = s[start+2:]
			continue
		}
		length := strings.IndexByte(s[start:], '}')
		if length < 0 || !variableName.MatchString(s[start+2:start+length]) {
			return "", fmt.Errorf("%s: a ${ must start a reference ${NAME} to an environment variable (write $${ for a literal ${)", at)
		}
		name := s[start+2 : start+length]
		value, set := os.LookupEnv(name)
		if !set {
			return "", fmt.Errorf("%s: the environment variable %s is not set", at, name)
		}
		out.WriteString(s[:start])
		out.WriteString(value)
		s = s[start+length+1:]
	}
}
