// Reading the configuration file and decoding it strictly.

package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Alex-Zechariah-02/apiward/internal/forward"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// loadNativeConfig reads and checks the configuration file at path. The
// controller checks the rest of its own settings, the admin address and the
// trust key, before it opens the database.
func loadNativeConfig(path string) (nativeConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return nativeConfig{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil {
		return nativeConfig{}, err
	}
	if len(data) > maxConfigBytes {
		return nativeConfig{}, fmt.Errorf("the file is larger than %d bytes", maxConfigBytes)
	}
	settings, err := decodeNativeFile(data)
	if err != nil {
		return nativeConfig{}, err
	}
	cfg, err := settings.check()
	if err != nil {
		return nativeConfig{}, err
	}
	settingsFile, err := filepath.Abs(path)
	cfg.controller.ReloadKeys = func() (pipeline.TrustConfig, *forward.Network, error) {
		reloaded, err := loadNativeConfig(settingsFile)
		return reloaded.controller.JWT, reloaded.controller.Network, err
	}
	return cfg, err
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

	var settings nativeFile
	if err := policy.DecodeStrict(data, &settings); err != nil {
		if typeErr, ok := errors.AsType[*json.UnmarshalTypeError](err); ok {
			return nativeFile{}, fmt.Errorf("%s: a JSON %s is not a valid value", typeErr.Field, typeErr.Value)
		}
		return nativeFile{}, errors.New(strings.TrimPrefix(err.Error(), "json: "))
	}
	return settings, nil
}
