package yamlutil

import (
	"strings"
	"testing"
)

func TestMarshalDeterministic_SortsMapKeys(t *testing.T) {
	// Maps with keys in different insertion orders should produce same output
	type testStruct struct {
		Name    string            `yaml:"name"`
		Options map[string]string `yaml:"options"`
	}

	data := testStruct{
		Name: "test",
		Options: map[string]string{
			"zebra":  "z",
			"alpha":  "a",
			"middle": "m",
		},
	}

	result, err := MarshalDeterministic(data)
	if err != nil {
		t.Fatalf("MarshalDeterministic failed: %v", err)
	}

	// Verify output has keys in alphabetical order
	output := string(result)
	alphaIdx := strings.Index(output, "alpha:")
	middleIdx := strings.Index(output, "middle:")
	zebraIdx := strings.Index(output, "zebra:")

	if alphaIdx == -1 || middleIdx == -1 || zebraIdx == -1 {
		t.Fatalf("missing expected keys in output: %s", output)
	}

	if alphaIdx >= middleIdx || middleIdx >= zebraIdx {
		t.Errorf("keys not in sorted order: alpha=%d, middle=%d, zebra=%d\nOutput:\n%s",
			alphaIdx, middleIdx, zebraIdx, output)
	}
}

func TestMarshalDeterministic_ConsistentAcrossCalls(t *testing.T) {
	type nested struct {
		B string `yaml:"b"`
		A string `yaml:"a"`
	}
	type testStruct struct {
		Items map[string]nested `yaml:"items"`
	}

	data := testStruct{
		Items: map[string]nested{
			"second": {B: "b2", A: "a2"},
			"first":  {B: "b1", A: "a1"},
		},
	}

	// Marshal multiple times
	var results [][]byte
	for i := 0; i < 10; i++ {
		result, err := MarshalDeterministic(data)
		if err != nil {
			t.Fatalf("marshal %d failed: %v", i, err)
		}
		results = append(results, result)
	}

	// All results should be identical
	for i := 1; i < len(results); i++ {
		if string(results[i]) != string(results[0]) {
			t.Errorf("marshal %d differs from marshal 0:\n--- Marshal 0 ---\n%s\n--- Marshal %d ---\n%s",
				i, results[0], i, results[i])
		}
	}
}

func TestMarshalDeterministic_NestedMaps(t *testing.T) {
	type deepStruct struct {
		Level1 map[string]map[string]string `yaml:"level1"`
	}

	data := deepStruct{
		Level1: map[string]map[string]string{
			"z": {"c": "3", "a": "1", "b": "2"},
			"a": {"y": "25", "x": "24", "z": "26"},
		},
	}

	result, err := MarshalDeterministic(data)
	if err != nil {
		t.Fatalf("MarshalDeterministic failed: %v", err)
	}

	output := string(result)

	// Top level: 'a' should come before 'z'
	aIdx := strings.Index(output, "  a:")
	zIdx := strings.Index(output, "  z:")
	if aIdx == -1 || zIdx == -1 {
		t.Fatalf("missing level1 keys in output: %s", output)
	}
	if aIdx > zIdx {
		t.Errorf("level1 keys not sorted: a=%d, z=%d", aIdx, zIdx)
	}
}

func TestMarshalDeterministic_EmptyMap(t *testing.T) {
	type testStruct struct {
		Empty map[string]string `yaml:"empty"`
	}

	data := testStruct{
		Empty: map[string]string{},
	}

	result, err := MarshalDeterministic(data)
	if err != nil {
		t.Fatalf("MarshalDeterministic failed: %v", err)
	}

	if len(result) == 0 {
		t.Error("expected non-empty output for struct with empty map")
	}
}

func TestMarshalDeterministic_Slice(t *testing.T) {
	type testStruct struct {
		Items []string `yaml:"items"`
	}

	data := testStruct{
		Items: []string{"zebra", "alpha", "middle"},
	}

	result, err := MarshalDeterministic(data)
	if err != nil {
		t.Fatalf("MarshalDeterministic failed: %v", err)
	}

	// Slices should NOT be reordered (only maps are sorted)
	output := string(result)
	zebraIdx := strings.Index(output, "zebra")
	alphaIdx := strings.Index(output, "alpha")
	middleIdx := strings.Index(output, "middle")

	if zebraIdx >= alphaIdx || alphaIdx >= middleIdx {
		t.Errorf("slice order was changed (should preserve original order): zebra=%d, alpha=%d, middle=%d",
			zebraIdx, alphaIdx, middleIdx)
	}
}

func TestMarshalDeterministic_SliceOfMaps(t *testing.T) {
	type testStruct struct {
		Items []map[string]string `yaml:"items"`
	}

	data := testStruct{
		Items: []map[string]string{
			{"z": "1", "a": "2"},
			{"b": "3", "c": "4"},
		},
	}

	result, err := MarshalDeterministic(data)
	if err != nil {
		t.Fatalf("MarshalDeterministic failed: %v", err)
	}

	output := string(result)

	// Within each map, keys should be sorted
	// First map: 'a' should come before 'z'
	lines := strings.Split(output, "\n")
	var firstA, firstZ int
	for i, line := range lines {
		if strings.Contains(line, "a:") && firstA == 0 {
			firstA = i
		}
		if strings.Contains(line, "z:") && firstZ == 0 {
			firstZ = i
		}
	}
	if firstA > firstZ {
		t.Errorf("map keys not sorted within slice element: a at line %d, z at line %d", firstA, firstZ)
	}
}

func TestSortYAMLNode_NilNode(t *testing.T) {
	// Should not panic on nil
	SortYAMLNode(nil)
}

func TestMarshalDeterministic_Indent(t *testing.T) {
	type nested struct {
		Value string `yaml:"value"`
	}
	type testStruct struct {
		Nested nested `yaml:"nested"`
	}

	data := testStruct{
		Nested: nested{Value: "test"},
	}

	result, err := MarshalDeterministic(data)
	if err != nil {
		t.Fatalf("MarshalDeterministic failed: %v", err)
	}

	// Verify 2-space indentation is used
	output := string(result)
	if !strings.Contains(output, "  value:") {
		t.Errorf("expected 2-space indentation, got:\n%s", output)
	}
}
