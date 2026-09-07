//go:build !onnxruntime_embedded

package broker

func platformEmbeddedONNXRuntimeBundle() (onnxRuntimeBundle, bool, error) {
	return onnxRuntimeBundle{}, false, nil
}
