package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/docker/attest/pkg/tuf"
	goyaml "gopkg.in/yaml.v3"
)

const (
	MappingFilename = "mapping.yaml"
)

func LoadLocalMappings(configDir string) (*PolicyMappings, error) {
	if configDir == "" {
		return nil, nil
	}
	mappings := &PolicyMappings{}
	path := filepath.Join(configDir, MappingFilename)
	mappingFile, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read local policy mapping file %s: %w", path, err)
	}
	err = goyaml.Unmarshal(mappingFile, mappings)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy mapping file %s: %w", path, err)
	}
	return mappings, nil
}

func LoadTufMappings(tufClient tuf.TUFClient, localTargetsDir string) (*PolicyMappings, error) {
	if tufClient == nil {
		return nil, fmt.Errorf("tuf client not set")
	}
	filename := MappingFilename
	_, fileContents, err := tufClient.DownloadTarget(filename, filepath.Join(localTargetsDir, filename))
	if err != nil {
		return nil, fmt.Errorf("failed to download policy mapping file %s: %w", filename, err)
	}
	mappings := &PolicyMappings{}

	err = goyaml.Unmarshal(fileContents, mappings)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy mapping file %s: %w", filename, err)
	}
	return mappings, nil
}
