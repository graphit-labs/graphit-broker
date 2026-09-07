//go:build onnxruntime_embedded

package broker

import (
	_ "embed"
	"strings"
)

//go:embed onnxruntime_payload.tar.gz
var embeddedONNXRuntimePayload []byte

func platformEmbeddedONNXRuntimeBundle() (onnxRuntimeBundle, bool, error) {
	bundle := onnxRuntimeBundle{
		version:       embeddedONNXRuntimeVersion,
		platform:      embeddedONNXRuntimePlatform,
		library:       embeddedONNXRuntimeLibrary,
		requiredFiles: strings.Split(embeddedONNXRuntimeRequiredFiles, ","),
		sha256:        embeddedONNXRuntimeBundleSHA256,
		payload:       embeddedONNXRuntimePayload,
	}
	if err := validateONNXRuntimeBundle(bundle); err != nil {
		return onnxRuntimeBundle{}, false, err
	}
	return bundle, true, nil
}
