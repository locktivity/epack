package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/safefile"
	"github.com/locktivity/epack/internal/safeyaml"
)

// ErrAlreadyExists is returned when a component already exists in the config.
var ErrAlreadyExists = errors.E(errors.AlreadyExists, "component already exists in config", nil)

// AddTool adds a tool entry to the config file.
// Returns ErrAlreadyExists if the tool is already defined.
// Preserves existing file formatting and comments.
func AddTool(configPath, name string, cfg ToolConfig) error {
	return addComponent(configPath, "tools", name, cfg)
}

// AddCollector adds a collector entry to the config file.
// Returns ErrAlreadyExists if the collector is already defined.
// Preserves existing file formatting and comments.
func AddCollector(configPath, name string, cfg CollectorConfig) error {
	return addComponent(configPath, "collectors", name, cfg)
}

// AddRemote adds a remote entry to the config file.
// Returns ErrAlreadyExists if the remote is already defined.
// Preserves existing file formatting and comments.
func AddRemote(configPath, name string, cfg RemoteConfig) error {
	return addComponent(configPath, "remotes", name, cfg)
}

// HasTool checks if a tool exists in the config file.
func HasTool(configPath, name string) (bool, error) {
	return hasComponent(configPath, "tools", name)
}

// HasCollector checks if a collector exists in the config file.
func HasCollector(configPath, name string) (bool, error) {
	return hasComponent(configPath, "collectors", name)
}

// HasRemote checks if a remote exists in the config file.
func HasRemote(configPath, name string) (bool, error) {
	return hasComponent(configPath, "remotes", name)
}

// hasComponent checks if a component exists under the given section.
func hasComponent(configPath, section, name string) (bool, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("reading config: %w", err)
	}

	root, err := safeyaml.DecodeNode(data, limits.ConfigFile)
	if err != nil {
		return false, fmt.Errorf("parsing config: %w", err)
	}

	sectionNode := findMappingKey(root, section)
	if sectionNode == nil {
		return false, nil
	}

	return findMappingKey(sectionNode, name) != nil, nil
}

// addComponent adds a component to the specified section of the config file.
func addComponent(configPath, section, name string, cfg any) error {
	root, docContent, err := readConfigDocument(configPath)
	if err != nil {
		return err
	}
	sectionNode := ensureSectionNode(docContent, section)

	// Check if component already exists
	if findMappingKey(sectionNode, name) != nil {
		return fmt.Errorf("%w: %s %q", ErrAlreadyExists, section[:len(section)-1], name)
	}

	// Create the component node
	componentNode, err := createComponentNode(cfg)
	if err != nil {
		return fmt.Errorf("creating component node: %w", err)
	}

	sectionNode.Content = append(sectionNode.Content,
		&safeyaml.Node{Kind: safeyaml.ScalarNode, Value: name},
		componentNode,
	)

	encoded, err := encodeConfigNode(root)
	if err != nil {
		return err
	}
	return writeConfigFile(configPath, encoded)
}

func readConfigDocument(configPath string) (*safeyaml.Node, *safeyaml.Node, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, nil, fmt.Errorf("reading config: %w", err)
	}

	root, err := safeyaml.DecodeNode(data, limits.ConfigFile)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing config: %w", err)
	}
	if root.Kind != safeyaml.DocumentNode || len(root.Content) == 0 {
		return nil, nil, fmt.Errorf("invalid config file: expected document node")
	}

	docContent := root.Content[0]
	if docContent.Kind != safeyaml.MappingNode {
		return nil, nil, fmt.Errorf("invalid config file: expected mapping at top level")
	}
	return root, docContent, nil
}

func ensureSectionNode(docContent *safeyaml.Node, section string) *safeyaml.Node {
	sectionNode := findMappingKey(docContent, section)
	if sectionNode == nil {
		sectionNode = &safeyaml.Node{Kind: safeyaml.MappingNode}
		docContent.Content = append(docContent.Content,
			&safeyaml.Node{Kind: safeyaml.ScalarNode, Value: section},
			sectionNode,
		)
		return sectionNode
	}

	if sectionNode.Kind != safeyaml.MappingNode {
		sectionNode.Kind = safeyaml.MappingNode
		sectionNode.Tag = ""
		sectionNode.Value = ""
		sectionNode.Content = nil
	}
	return sectionNode
}

func encodeConfigNode(root *safeyaml.Node) ([]byte, error) {
	var buf bytes.Buffer
	encoder := safeyaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(root); err != nil {
		return nil, fmt.Errorf("encoding config: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return nil, fmt.Errorf("closing encoder: %w", err)
	}
	return buf.Bytes(), nil
}

func writeConfigFile(configPath string, data []byte) error {
	absPath, err := filepath.Abs(configPath)
	if err != nil {
		return fmt.Errorf("resolving config path: %w", err)
	}
	baseDir := filepath.Dir(absPath)
	fileName := filepath.Base(absPath)
	if err := safefile.WriteFile(baseDir, fileName, data); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}
	return nil
}

// findMappingKey finds a key in a mapping node and returns its value node.
// Returns nil if not found.
func findMappingKey(node *safeyaml.Node, key string) *safeyaml.Node {
	if node == nil {
		return nil
	}

	// Handle document node - look inside content
	if node.Kind == safeyaml.DocumentNode && len(node.Content) > 0 {
		return findMappingKey(node.Content[0], key)
	}

	if node.Kind != safeyaml.MappingNode {
		return nil
	}

	// Mapping nodes have key-value pairs in Content
	for i := 0; i < len(node.Content)-1; i += 2 {
		keyNode := node.Content[i]
		valueNode := node.Content[i+1]

		if keyNode.Kind == safeyaml.ScalarNode && keyNode.Value == key {
			return valueNode
		}
	}

	return nil
}

// createComponentNode creates a safeyaml.Node tree from a component config.
func createComponentNode(cfg any) (*safeyaml.Node, error) {
	// Marshal to YAML first, then parse back to get a node
	data, err := safeyaml.Marshal(cfg)
	if err != nil {
		return nil, err
	}

	// Use DecodeNode to parse into a node tree
	// The data size is small (single component config), so use a reasonable limit
	node, err := safeyaml.DecodeNode(data, limits.ConfigFile)
	if err != nil {
		return nil, err
	}

	// The result is a document node; return its content
	if node.Kind == safeyaml.DocumentNode && len(node.Content) > 0 {
		return node.Content[0], nil
	}

	return node, nil
}
