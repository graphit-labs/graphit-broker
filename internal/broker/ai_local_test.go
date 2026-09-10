package broker

import (
	"errors"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	ort "github.com/yalue/onnxruntime_go"
)

var errTestGPUOOM = errors.New("CUDA failure 2: out of memory")

type fakeLocalONNXSession struct {
	name      string
	errors    []error
	calls     int
	destroyed int
	events    *[]string
}

func (s *fakeLocalONNXSession) Run(_ []ort.Value, _ []ort.Value) error {
	s.calls++
	if s.events != nil {
		*s.events = append(*s.events, s.name)
	}
	if len(s.errors) == 0 {
		return nil
	}
	err := s.errors[0]
	s.errors = s.errors[1:]
	return err
}

func (s *fakeLocalONNXSession) Destroy() error {
	s.destroyed++
	return nil
}

type fakeLocalClock struct {
	now time.Time
}

func (c *fakeLocalClock) Now() time.Time {
	return c.now
}

func recoveryState(router *localONNXSessionRouter) (bool, time.Time) {
	router.mu.Lock()
	defer router.mu.Unlock()
	return router.usingCPU, router.nextAcceleratedAttempt
}

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
	_, _, err := newLocalONNXSession("unused.onnx", nil, nil, UpstreamConfig{Device: "coreml"})
	if err == nil || !strings.Contains(err.Error(), "supported only on macOS") {
		t.Fatalf("CoreML session error=%v", err)
	}
}

func TestAutoDeviceOOMImmediatelyRetriesSameInferenceOnCPU(t *testing.T) {
	clock := &fakeLocalClock{now: time.Unix(1_000, 0)}
	events := []string{}
	gpu := &fakeLocalONNXSession{name: "cuda", errors: []error{errTestGPUOOM}, events: &events}
	cpu := &fakeLocalONNXSession{name: "cpu", events: &events}
	factoryCalls := 0
	router := newLocalONNXSessionRouterForDevice("auto", "cuda", gpu, func() (localONNXSession, error) {
		factoryCalls++
		return cpu, nil
	}, clock.Now)

	request := "same-request"
	if err := router.execute(func(session localONNXSession) error {
		if request != "same-request" {
			t.Fatalf("request changed during fallback: %q", request)
		}
		if session == gpu {
			clock.now = clock.now.Add(30 * time.Second)
		}
		return session.Run(nil, nil)
	}); err != nil {
		t.Fatalf("auto inference failed: %v", err)
	}
	if got := strings.Join(events, ","); got != "cuda,cpu" {
		t.Fatalf("execution order=%q, want cuda,cpu", got)
	}
	if factoryCalls != 1 {
		t.Fatalf("CPU factory calls=%d, want 1", factoryCalls)
	}
	usingCPU, next := recoveryState(router)
	if !usingCPU || next.Sub(clock.now) != time.Minute {
		t.Fatalf("fallback state usingCPU=%v next=%s, want true and 1m", usingCPU, next.Sub(clock.now))
	}
}

func TestAutoDeviceRecoveryUsesCappedExponentialBackoff(t *testing.T) {
	clock := &fakeLocalClock{now: time.Unix(2_000, 0)}
	gpu := &fakeLocalONNXSession{name: "cuda", errors: []error{
		errTestGPUOOM, errTestGPUOOM, errTestGPUOOM, errTestGPUOOM, errTestGPUOOM, errTestGPUOOM,
	}}
	cpu := &fakeLocalONNXSession{name: "cpu"}
	router := newLocalONNXSessionRouterForDevice("auto", "cuda", gpu, func() (localONNXSession, error) {
		return cpu, nil
	}, clock.Now)
	run := func(session localONNXSession) error { return session.Run(nil, nil) }

	for i, wantDelay := range []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 10 * time.Minute, 10 * time.Minute} {
		if i > 0 {
			_, next := recoveryState(router)
			clock.now = next
		}
		if err := router.execute(run); err != nil {
			t.Fatalf("OOM attempt %d failed after CPU fallback: %v", i+1, err)
		}
		usingCPU, next := recoveryState(router)
		if !usingCPU || next.Sub(clock.now) != wantDelay {
			t.Fatalf("attempt %d usingCPU=%v delay=%s, want true and %s", i+1, usingCPU, next.Sub(clock.now), wantDelay)
		}
	}

	_, next := recoveryState(router)
	clock.now = next
	if err := router.execute(run); err != nil {
		t.Fatalf("successful GPU recovery failed: %v", err)
	}
	usingCPU, next := recoveryState(router)
	if usingCPU || !next.IsZero() {
		t.Fatalf("successful recovery state usingCPU=%v next=%v", usingCPU, next)
	}
	if err := router.execute(run); err != nil {
		t.Fatalf("post-recovery GPU inference failed: %v", err)
	}
	if gpu.calls != 8 || cpu.calls != 6 {
		t.Fatalf("calls gpu=%d cpu=%d, want gpu=8 cpu=6", gpu.calls, cpu.calls)
	}
}

func TestAutoDeviceReactivatesOnlyAfterCompleteInferenceSuccess(t *testing.T) {
	clock := &fakeLocalClock{now: time.Unix(3_000, 0)}
	gpu := &fakeLocalONNXSession{name: "cuda", errors: []error{errTestGPUOOM}}
	cpu := &fakeLocalONNXSession{name: "cpu"}
	router := newLocalONNXSessionRouterForDevice("auto", "cuda", gpu, func() (localONNXSession, error) {
		return cpu, nil
	}, clock.Now)
	run := func(session localONNXSession) error { return session.Run(nil, nil) }

	if err := router.execute(run); err != nil {
		t.Fatalf("initial CPU fallback failed: %v", err)
	}
	usingCPU, next := recoveryState(router)
	clock.now = next
	postprocessErr := errors.New("invalid accelerated output")
	if err := router.execute(func(session localONNXSession) error {
		if err := session.Run(nil, nil); err != nil {
			return err
		}
		if session == gpu {
			return postprocessErr
		}
		return nil
	}); !errors.Is(err, postprocessErr) {
		t.Fatalf("recovery result=%v, want post-processing error", err)
	}
	usingCPU, next = recoveryState(router)
	if !usingCPU || next.Sub(clock.now) != 2*time.Minute {
		t.Fatalf("failed full inference reactivated GPU: usingCPU=%v delay=%s", usingCPU, next.Sub(clock.now))
	}

	clock.now = next.Add(-time.Second)
	if err := router.execute(run); err != nil {
		t.Fatalf("CPU inference before next probe failed: %v", err)
	}
	if cpu.calls != 2 {
		t.Fatalf("CPU calls=%d, want 2", cpu.calls)
	}
	clock.now = next
	if err := router.execute(run); err != nil {
		t.Fatalf("complete GPU inference failed: %v", err)
	}
	usingCPU, _ = recoveryState(router)
	if usingCPU {
		t.Fatal("GPU remained disabled after complete successful inference")
	}
}

func TestExplicitDeviceModesRemainStrict(t *testing.T) {
	for _, mode := range []string{"cpu", "cuda", "coreml"} {
		t.Run(mode, func(t *testing.T) {
			primary := &fakeLocalONNXSession{name: mode, errors: []error{errTestGPUOOM}}
			factoryCalls := 0
			router := newLocalONNXSessionRouterForDevice(mode, mode, primary, func() (localONNXSession, error) {
				factoryCalls++
				return &fakeLocalONNXSession{name: "unexpected"}, nil
			}, time.Now)
			err := router.execute(func(session localONNXSession) error { return session.Run(nil, nil) })
			if !errors.Is(err, errTestGPUOOM) {
				t.Fatalf("explicit %s error=%v, want original OOM", mode, err)
			}
			if primary.calls != 1 || factoryCalls != 0 {
				t.Fatalf("explicit %s calls=%d factoryCalls=%d, want 1 and 0", mode, primary.calls, factoryCalls)
			}
			usingCPU, next := recoveryState(router)
			if usingCPU || !next.IsZero() {
				t.Fatalf("explicit %s entered recovery: usingCPU=%v next=%v", mode, usingCPU, next)
			}
		})
	}
}

func TestAutoDeviceDoesNotSwitchWithoutAcceleratorOOM(t *testing.T) {
	for _, tc := range []struct {
		name, device string
		runErr       error
	}{
		{name: "accelerator non-OOM", device: "cuda", runErr: errors.New("invalid input shape")},
		{name: "auto started on CPU", device: "cpu", runErr: errTestGPUOOM},
	} {
		t.Run(tc.name, func(t *testing.T) {
			primary := &fakeLocalONNXSession{name: tc.device, errors: []error{tc.runErr}}
			factoryCalls := 0
			router := newLocalONNXSessionRouterForDevice("auto", tc.device, primary, func() (localONNXSession, error) {
				factoryCalls++
				return &fakeLocalONNXSession{name: "unexpected"}, nil
			}, time.Now)
			if err := router.execute(func(session localONNXSession) error { return session.Run(nil, nil) }); !errors.Is(err, tc.runErr) {
				t.Fatalf("error=%v, want %v", err, tc.runErr)
			}
			usingCPU, next := recoveryState(router)
			if primary.calls != 1 || factoryCalls != 0 || usingCPU || !next.IsZero() {
				t.Fatalf("calls=%d factory=%d usingCPU=%v next=%v", primary.calls, factoryCalls, usingCPU, next)
			}
		})
	}
}

func TestAutoDeviceRecoveryTransitionsAreSynchronized(t *testing.T) {
	clock := &fakeLocalClock{now: time.Unix(4_000, 0)}
	gpu := &fakeLocalONNXSession{name: "cuda", errors: []error{errTestGPUOOM}}
	cpu := &fakeLocalONNXSession{name: "cpu"}
	router := newLocalONNXSessionRouterForDevice("auto", "cuda", gpu, func() (localONNXSession, error) {
		return cpu, nil
	}, clock.Now)
	run := func(session localONNXSession) error { return session.Run(nil, nil) }
	if err := router.execute(run); err != nil {
		t.Fatalf("initial CPU fallback failed: %v", err)
	}
	_, next := recoveryState(router)
	clock.now = next

	const concurrentCalls = 64
	var wg sync.WaitGroup
	errorsSeen := make(chan error, concurrentCalls)
	for range concurrentCalls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := router.execute(run); err != nil {
				errorsSeen <- err
			}
		}()
	}
	wg.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Errorf("concurrent inference failed: %v", err)
	}
	usingCPU, _ := recoveryState(router)
	if usingCPU {
		t.Fatal("GPU was not reactivated by the successful synchronized probe")
	}
	if gpu.calls != concurrentCalls+1 || cpu.calls != 1 {
		t.Fatalf("calls gpu=%d cpu=%d, want gpu=%d cpu=1", gpu.calls, cpu.calls, concurrentCalls+1)
	}
}

func TestAcceleratorOutOfMemoryDetection(t *testing.T) {
	for _, message := range []string{
		"CUDA failure 2: out of memory",
		"CUDA_ERROR_OUT_OF_MEMORY",
		"cudaErrorMemoryAllocation",
		"CUBLAS_STATUS_ALLOC_FAILED",
	} {
		if !isAcceleratorOutOfMemory(errors.New(message)) {
			t.Errorf("OOM message was not recognized: %q", message)
		}
	}
	for _, message := range []string{"invalid input shape", "provider unavailable", "deadline exceeded"} {
		if isAcceleratorOutOfMemory(errors.New(message)) {
			t.Errorf("non-OOM message was misclassified: %q", message)
		}
	}
}
