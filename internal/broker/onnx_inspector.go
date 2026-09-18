package broker

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"

	ort "github.com/yalue/onnxruntime_go"
)

type ONNXTensorInfo struct {
	Name        string  `json:"name"`
	ElementType string  `json:"element_type"`
	Dimensions  []int64 `json:"dimensions"`
}

type ONNXInspection struct {
	Inputs       []ONNXTensorInfo  `json:"inputs"`
	Outputs      []ONNXTensorInfo  `json:"outputs"`
	Opsets       map[string]int64  `json:"opsets,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	ExternalData []string          `json:"external_data,omitempty"`
}

type ONNXInspector struct{}

func (ONNXInspector) Inspect(path string) (ONNXInspection, error) {
	if err := initializeONNXRuntime(); err != nil {
		return ONNXInspection{}, err
	}
	inputs, outputs, err := ort.GetInputOutputInfo(path)
	if err != nil {
		return ONNXInspection{}, fmt.Errorf("load ONNX signature: %w", err)
	}
	inspection := ONNXInspection{Opsets: map[string]int64{}, Metadata: map[string]string{}}
	for _, input := range inputs {
		inspection.Inputs = append(inspection.Inputs, ONNXTensorInfo{Name: input.Name, ElementType: input.DataType.String(), Dimensions: append([]int64(nil), input.Dimensions...)})
	}
	for _, output := range outputs {
		inspection.Outputs = append(inspection.Outputs, ONNXTensorInfo{Name: output.Name, ElementType: output.DataType.String(), Dimensions: append([]int64(nil), output.Dimensions...)})
	}
	metadata, err := inspectONNXWire(path)
	if err != nil {
		return ONNXInspection{}, fmt.Errorf("inspect ONNX metadata: %w", err)
	}
	inspection.Opsets, inspection.Metadata, inspection.ExternalData = metadata.Opsets, metadata.Metadata, metadata.ExternalData
	return inspection, nil
}

func inspectONNX(path string) (ONNXInspection, error) {
	return (ONNXInspector{}).Inspect(path)
}

func resolveModelSemantics(model *ResolvedModel) error {
	for _, external := range model.Inspection.ExternalData {
		path, err := secureBundlePath(model.BundleDir, external)
		if err != nil {
			return fmt.Errorf("ONNX external data %q: %w", external, err)
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("ONNX external data %q is missing or not a regular file", external)
		}
		digest, err := fileSHA256(path)
		if err != nil {
			return fmt.Errorf("hash ONNX external data %q: %w", external, err)
		}
		model.ArtifactSHA["external:"+external] = digest
	}
	inputMapping, inputNames, err := resolveInputMapping(model.Manifest.Inference.Inputs, model.Inspection.Inputs)
	if err != nil {
		return err
	}
	output, err := resolveOutput(model.Manifest.Task, model.Manifest.Inference.Output, model.Inspection.Outputs)
	if err != nil {
		return err
	}
	model.InputSemantic, model.InputNames, model.OutputName = inputMapping, inputNames, output.Name
	switch model.Manifest.Task {
	case "embedding":
		rank := len(output.Dimensions)
		pooling := model.Manifest.Inference.Pooling
		if pooling == "none" && rank != 2 {
			return fmt.Errorf("embedding output %q has rank %d; pooling none requires rank 2", output.Name, rank)
		}
		if pooling != "none" && rank != 3 {
			return fmt.Errorf("embedding output %q has rank %d; pooling %s requires rank 3", output.Name, rank, pooling)
		}
		if output.ElementType != ort.TensorElementDataType(ort.TensorElementDataTypeFloat).String() {
			return fmt.Errorf("embedding output %q type %s is unsupported; expected float32", output.Name, output.ElementType)
		}
		inferred := 0
		if rank > 0 && output.Dimensions[rank-1] > 0 {
			inferred = int(output.Dimensions[rank-1])
		}
		if model.Manifest.Inference.Dimensions != nil {
			model.Dimensions = *model.Manifest.Inference.Dimensions
			if inferred > 0 && inferred != model.Dimensions {
				return fmt.Errorf("embedding dimensions override %d conflicts with static ONNX dimension %d", model.Dimensions, inferred)
			}
		} else {
			model.Dimensions = inferred
		}
		if model.Dimensions <= 0 {
			return errors.New("embedding dimensions are dynamic and inference.dimensions was not provided")
		}
	case "rerank":
		if len(output.Dimensions) != 1 && len(output.Dimensions) != 2 {
			return fmt.Errorf("rerank output %q has rank %d; expected rank 1 or 2", output.Name, len(output.Dimensions))
		}
		if output.ElementType != ort.TensorElementDataType(ort.TensorElementDataTypeFloat).String() {
			return fmt.Errorf("rerank output %q type %s is unsupported; expected float32", output.Name, output.ElementType)
		}
	}
	return finalizeModelIdentity(model)
}

func resolveInputMapping(spec ModelInputManifest, inputs []ONNXTensorInfo) (map[string]string, []string, error) {
	semanticToName := map[string]string{}
	if spec.Auto {
		semanticToName["input_ids"] = "input_ids"
		semanticToName["attention_mask"] = "attention_mask"
		semanticToName["token_type_ids"] = "token_type_ids"
	} else {
		semanticToName["input_ids"] = spec.InputIDs
		semanticToName["attention_mask"] = spec.AttentionMask
		semanticToName["token_type_ids"] = spec.TokenTypeIDs
	}
	nameToSemantic := map[string]string{}
	for semantic, name := range semanticToName {
		if name != "" {
			nameToSemantic[name] = semantic
		}
	}
	ordered := make([]string, 0, len(inputs))
	found := map[string]bool{}
	for _, input := range inputs {
		semantic := nameToSemantic[input.Name]
		if semantic == "" {
			return nil, nil, fmt.Errorf("ONNX input %q has no supported semantic mapping", input.Name)
		}
		if input.ElementType != ort.TensorElementDataType(ort.TensorElementDataTypeInt64).String() || len(input.Dimensions) != 2 {
			return nil, nil, fmt.Errorf("ONNX input %q must be a rank-2 int64 tensor", input.Name)
		}
		found[semantic] = true
		ordered = append(ordered, input.Name)
	}
	if !found["input_ids"] || !found["attention_mask"] {
		return nil, nil, errors.New("ONNX model must map input_ids and attention_mask")
	}
	return nameToSemantic, ordered, nil
}

func resolveOutput(task, requested string, outputs []ONNXTensorInfo) (ONNXTensorInfo, error) {
	if len(outputs) == 0 {
		return ONNXTensorInfo{}, errors.New("ONNX model declares no outputs")
	}
	if requested != "" && requested != "auto" {
		for _, output := range outputs {
			if output.Name == requested {
				return output, nil
			}
		}
		return ONNXTensorInfo{}, fmt.Errorf("configured output %q does not exist", requested)
	}
	preferred := "sentence_embedding"
	if task == "rerank" {
		preferred = "logits"
	}
	for _, output := range outputs {
		if output.Name == preferred {
			return output, nil
		}
	}
	if len(outputs) == 1 {
		return outputs[0], nil
	}
	return ONNXTensorInfo{}, fmt.Errorf("ONNX model has %d outputs and none matches known %s profile; set inference.output", len(outputs), task)
}

type onnxWireMetadata struct {
	Opsets       map[string]int64
	Metadata     map[string]string
	ExternalData []string
}

func inspectONNXWire(path string) (onnxWireMetadata, error) {
	f, err := os.Open(path)
	if err != nil {
		return onnxWireMetadata{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return onnxWireMetadata{}, err
	}
	result := onnxWireMetadata{Opsets: map[string]int64{}, Metadata: map[string]string{}}
	r := io.NewSectionReader(f, 0, info.Size())
	for {
		field, wire, err := readWireTag(r)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return result, err
		}
		switch {
		case field == 8 && wire == 2:
			nested, err := readWireSection(r)
			if err != nil {
				return result, err
			}
			domain, version, err := parseOpset(nested)
			if err != nil {
				return result, err
			}
			result.Opsets[domain] = version
		case field == 14 && wire == 2:
			nested, err := readWireSection(r)
			if err != nil {
				return result, err
			}
			key, value, err := parseStringPair(nested)
			if err != nil {
				return result, err
			}
			result.Metadata[key] = value
		case field == 7 && wire == 2:
			nested, err := readWireSection(r)
			if err != nil {
				return result, err
			}
			external, err := parseGraphExternalData(nested)
			if err != nil {
				return result, err
			}
			result.ExternalData = append(result.ExternalData, external...)
		default:
			if err := skipWireValue(r, wire); err != nil {
				return result, err
			}
		}
	}
	sort.Strings(result.ExternalData)
	result.ExternalData = compactStrings(result.ExternalData)
	return result, nil
}

func parseOpset(r *io.SectionReader) (string, int64, error) {
	var domain string
	var version int64
	for {
		field, wire, err := readWireTag(r)
		if errors.Is(err, io.EOF) {
			return domain, version, nil
		}
		if err != nil {
			return "", 0, err
		}
		switch {
		case field == 1 && wire == 2:
			value, err := readWireBytes(r)
			if err != nil {
				return "", 0, err
			}
			domain = string(value)
		case field == 2 && wire == 0:
			value, err := readWireVarint(r)
			if err != nil {
				return "", 0, err
			}
			version = int64(value)
		default:
			if err := skipWireValue(r, wire); err != nil {
				return "", 0, err
			}
		}
	}
}

func parseStringPair(r *io.SectionReader) (string, string, error) {
	var key, value string
	for {
		field, wire, err := readWireTag(r)
		if errors.Is(err, io.EOF) {
			return key, value, nil
		}
		if err != nil {
			return "", "", err
		}
		if wire == 2 && (field == 1 || field == 2) {
			data, err := readWireBytes(r)
			if err != nil {
				return "", "", err
			}
			if field == 1 {
				key = string(data)
			} else {
				value = string(data)
			}
		} else if err := skipWireValue(r, wire); err != nil {
			return "", "", err
		}
	}
}

func parseGraphExternalData(r *io.SectionReader) ([]string, error) {
	var result []string
	for {
		field, wire, err := readWireTag(r)
		if errors.Is(err, io.EOF) {
			return result, nil
		}
		if err != nil {
			return nil, err
		}
		if field == 5 && wire == 2 {
			tensor, err := readWireSection(r)
			if err != nil {
				return nil, err
			}
			paths, err := parseTensorExternalData(tensor)
			if err != nil {
				return nil, err
			}
			result = append(result, paths...)
		} else if field == 15 && wire == 2 {
			sparse, err := readWireSection(r)
			if err != nil {
				return nil, err
			}
			paths, err := parseSparseExternalData(sparse)
			if err != nil {
				return nil, err
			}
			result = append(result, paths...)
		} else if err := skipWireValue(r, wire); err != nil {
			return nil, err
		}
	}
}

func parseSparseExternalData(r *io.SectionReader) ([]string, error) {
	var result []string
	for {
		field, wire, err := readWireTag(r)
		if errors.Is(err, io.EOF) {
			return result, nil
		}
		if err != nil {
			return nil, err
		}
		if (field == 1 || field == 2) && wire == 2 {
			tensor, err := readWireSection(r)
			if err != nil {
				return nil, err
			}
			paths, err := parseTensorExternalData(tensor)
			if err != nil {
				return nil, err
			}
			result = append(result, paths...)
		} else if err := skipWireValue(r, wire); err != nil {
			return nil, err
		}
	}
}

func parseTensorExternalData(r *io.SectionReader) ([]string, error) {
	var result []string
	for {
		field, wire, err := readWireTag(r)
		if errors.Is(err, io.EOF) {
			return result, nil
		}
		if err != nil {
			return nil, err
		}
		if field == 13 && wire == 2 {
			entry, err := readWireSection(r)
			if err != nil {
				return nil, err
			}
			key, value, err := parseStringPair(entry)
			if err != nil {
				return nil, err
			}
			if key == "location" && value != "" {
				result = append(result, value)
			}
		} else if err := skipWireValue(r, wire); err != nil {
			return nil, err
		}
	}
}

func readWireTag(r io.Reader) (int, int, error) {
	value, err := readWireVarint(r)
	if err != nil {
		return 0, 0, err
	}
	field, wire := int(value>>3), int(value&7)
	if field <= 0 {
		return 0, 0, errors.New("invalid protobuf field number")
	}
	return field, wire, nil
}

func readWireVarint(r io.Reader) (uint64, error) {
	var value uint64
	for shift := uint(0); shift < 64; shift += 7 {
		var b [1]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, err
		}
		value |= uint64(b[0]&0x7f) << shift
		if b[0] < 0x80 {
			return value, nil
		}
	}
	return 0, errors.New("protobuf varint overflow")
}

func readWireSection(r *io.SectionReader) (*io.SectionReader, error) {
	length, err := readWireVarint(r)
	if err != nil {
		return nil, err
	}
	start, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}
	if length > uint64(r.Size()-start) {
		return nil, io.ErrUnexpectedEOF
	}
	nested := io.NewSectionReader(r, start, int64(length))
	_, err = r.Seek(int64(length), io.SeekCurrent)
	return nested, err
}

func readWireBytes(r *io.SectionReader) ([]byte, error) {
	length, err := readWireVarint(r)
	if err != nil {
		return nil, err
	}
	if length > 16<<20 {
		return nil, errors.New("protobuf string field exceeds inspection limit")
	}
	data := make([]byte, int(length))
	_, err = io.ReadFull(r, data)
	return data, err
}

func skipWireValue(r *io.SectionReader, wire int) error {
	switch wire {
	case 0:
		_, err := readWireVarint(r)
		return err
	case 1:
		_, err := r.Seek(8, io.SeekCurrent)
		return err
	case 2:
		length, err := readWireVarint(r)
		if err != nil {
			return err
		}
		_, err = r.Seek(int64(length), io.SeekCurrent)
		return err
	case 5:
		_, err := r.Seek(4, io.SeekCurrent)
		return err
	default:
		return fmt.Errorf("unsupported protobuf wire type %d", wire)
	}
}

func compactStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}
