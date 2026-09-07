package broker

import (
	"runtime"
	"strings"
	"testing"
)

func TestCUDADeviceAvailabilityOverride(t *testing.T) {
	t.Setenv("GRAPHIT_BROKER_CUDA_AVAILABLE", "true")
	if !cudaDeviceAvailable() {
		t.Fatal("explicit CUDA availability was ignored")
	}
	t.Setenv("GRAPHIT_BROKER_CUDA_AVAILABLE", "false")
	if cudaDeviceAvailable() {
		t.Fatal("explicit CPU-only override was ignored")
	}
}

func TestLocalDeviceCandidatePolicy(t *testing.T) {
	tests := []struct {
		device          string
		cudaAvailable   bool
		coreMLAvailable bool
		want            string
	}{
		{device: "auto", cudaAvailable: true, want: "cuda,cpu"},
		{device: "auto", coreMLAvailable: true, want: "coreml,cpu"},
		{device: "auto", cudaAvailable: true, coreMLAvailable: true, want: "coreml,cuda,cpu"},
		{device: "auto", want: "cpu"},
		{device: "cpu", cudaAvailable: true, coreMLAvailable: true, want: "cpu"},
		{device: "cuda", want: "cuda"},
		{device: "coreml", want: "coreml"},
	}
	for _, tc := range tests {
		if got := strings.Join(localDeviceCandidates(tc.device, tc.cudaAvailable, tc.coreMLAvailable), ","); got != tc.want {
			t.Errorf("device=%s cudaAvailable=%v candidates=%q want=%q", tc.device, tc.cudaAvailable, got, tc.want)
		}
	}
}

func TestCoreMLPlatformPolicy(t *testing.T) {
	if err := validateLocalDevicePlatform("coreml", "linux"); err == nil || !strings.Contains(err.Error(), "only on macOS") {
		t.Fatalf("non-macOS CoreML error=%v", err)
	}
	if err := validateLocalDevicePlatform("coreml", "darwin"); err != nil {
		t.Fatalf("macOS CoreML rejected: %v", err)
	}
	if err := validateLocalDevicePlatform("cuda", "linux"); err != nil {
		t.Fatalf("CUDA policy changed: %v", err)
	}
}

func TestExplicitCoreMLSessionFailsClearlyOutsideMacOS(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("non-macOS behavior")
	}
	_, _, err := newLocalONNXSession("unused.onnx", nil, nil, LocalModelConfig{Device: "coreml"})
	if err == nil || !strings.Contains(err.Error(), "supported only on macOS") {
		t.Fatalf("CoreML session error=%v", err)
	}
}
