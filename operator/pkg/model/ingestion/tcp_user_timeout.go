// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/pkg/annotation"
)

var tcpUserTimeoutComponent = regexp.MustCompile(`([0-9]+(?:\.[0-9]*)?|\.[0-9]+)(ns|us|µs|μs|ms|s|m|h)`)

// parseTCPUserTimeout preserves Go duration syntax but validates decimal parts
// exactly: time.ParseDuration truncates each component below one nanosecond,
// which could silently turn a nonzero timeout into an explicit opt-out.
func parseTCPUserTimeout(value string) (time.Duration, error) {
	timeout, err := time.ParseDuration(value)
	if err != nil {
		return 0, err
	}
	if !strings.Contains(value, ".") {
		return timeout, model.ValidateTCPUserTimeout(timeout)
	}

	// Syntax and units were validated above. Sum exact rational milliseconds so
	// combinations such as 500us500us remain valid without rounding any part.
	milliseconds := new(big.Rat)
	for _, component := range tcpUserTimeoutComponent.FindAllStringSubmatch(value, -1) {
		amount, _ := new(big.Rat).SetString(component[1])
		unit, _ := time.ParseDuration("1" + component[2])
		amount.Mul(amount, big.NewRat(int64(unit), int64(time.Millisecond)))
		milliseconds.Add(milliseconds, amount)
	}
	if strings.HasPrefix(value, "-") {
		milliseconds.Neg(milliseconds)
	}
	if !milliseconds.IsInt() || milliseconds.Sign() < 0 || milliseconds.Cmp(big.NewRat(model.MaxTCPUserTimeout.Milliseconds(), 1)) > 0 {
		return 0, fmt.Errorf("TCP user timeout must be an exact whole number of milliseconds between 0 and %dms", model.MaxTCPUserTimeout.Milliseconds())
	}
	return time.Duration(milliseconds.Num().Int64()) * time.Millisecond, nil
}

// ApplyBackendTCPUserTimeouts attaches Service-owned timeout overrides to HTTP
// backends, including mirrors. Only referenced Services are validated. An
// invalid annotation prevents publishing a partially updated CEC.
func ApplyBackendTCPUserTimeouts(m *model.Model, services []corev1.Service) error {
	byName := make(map[types.NamespacedName]*corev1.Service, len(services))
	for i := range services {
		svc := &services[i]
		byName[types.NamespacedName{Namespace: svc.Namespace, Name: svc.Name}] = svc
	}

	timeouts := make(map[types.NamespacedName]*time.Duration)
	for backend := range m.HTTPBackends() {
		key := types.NamespacedName{Namespace: backend.Namespace, Name: backend.Name}
		if _, exists := timeouts[key]; exists {
			continue
		}
		timeouts[key] = nil
		svc := byName[key]
		if svc == nil {
			continue
		}
		value, present := svc.Annotations[annotation.ServiceUpstreamTCPUserTimeout]
		if !present {
			continue
		}
		timeout, err := parseTCPUserTimeout(value)
		if err != nil {
			return fmt.Errorf("Service %s has invalid %s annotation: %w", key, annotation.ServiceUpstreamTCPUserTimeout, err)
		}
		timeouts[key] = &timeout
	}

	for backend := range m.HTTPBackends() {
		backend.TCPUserTimeout = timeouts[types.NamespacedName{Namespace: backend.Namespace, Name: backend.Name}]
	}
	return nil
}
