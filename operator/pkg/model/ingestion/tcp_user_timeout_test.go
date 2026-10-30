// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/pkg/annotation"
)

func TestApplyBackendTCPUserTimeouts(t *testing.T) {
	backend := func(ns, name string, port uint32) model.Backend {
		return model.Backend{Namespace: ns, Name: name, Port: &model.BackendPort{Port: port}}
	}
	m := &model.Model{HTTP: []model.HTTPListener{{Routes: []model.HTTPRoute{{
		Backends:       []model.Backend{backend("default", "backend", 8080), backend("default", "backend", 9090), backend("other", "backend", 8080), backend("default", "missing", 8080)},
		RequestMirrors: []*model.HTTPRequestMirror{{Backend: ptr.To(backend("default", "backend", 8080))}},
	}}}}}
	svc := corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "backend"}}
	unrelated := corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "unrelated", Annotations: map[string]string{annotation.ServiceUpstreamTCPUserTimeout: "invalid"}}}
	for _, tc := range []struct {
		value *string
		want  *time.Duration
	}{
		{nil, nil},
		{ptr.To("60s"), ptr.To(time.Minute)},
		{ptr.To("300s"), ptr.To(5 * time.Minute)},
		{ptr.To("0s"), ptr.To(time.Duration(0))},
		{ptr.To("-0.0s"), ptr.To(time.Duration(0))},
		{ptr.To("1ms"), ptr.To(time.Millisecond)},
		{ptr.To("0.001s"), ptr.To(time.Millisecond)},
		{ptr.To("+.001s"), ptr.To(time.Millisecond)},
		{ptr.To("1.s"), ptr.To(time.Second)},
		{ptr.To("1000us"), ptr.To(time.Millisecond)},
		{ptr.To("500us500us"), ptr.To(time.Millisecond)},
		{ptr.To(".5ms.5ms"), ptr.To(time.Millisecond)},
		{ptr.To("500.0µs500.0μs"), ptr.To(time.Millisecond)},
		{ptr.To("0001ms0.0ns"), ptr.To(time.Millisecond)},
		{ptr.To("0.1ns0.9ns999999ns"), ptr.To(time.Millisecond)},
		{ptr.To("2147483647ms"), ptr.To(model.MaxTCPUserTimeout)},
		{ptr.To("2147483647.0ms"), ptr.To(model.MaxTCPUserTimeout)},
		{nil, nil},
	} {
		svc.Annotations = nil
		if tc.value != nil {
			svc.Annotations = map[string]string{annotation.ServiceUpstreamTCPUserTimeout: *tc.value}
		}
		require.NoError(t, ApplyBackendTCPUserTimeouts(m, []corev1.Service{svc, unrelated}))
		for be := range m.HTTPBackends() {
			if be.Namespace == svc.Namespace && be.Name == svc.Name {
				require.Equal(t, tc.want, be.TCPUserTimeout)
			} else {
				require.Nil(t, be.TCPUserTimeout)
			}
		}
	}
}

func TestApplyBackendTCPUserTimeoutsRejectsInvalidAtomically(t *testing.T) {
	for _, invalid := range []string{
		"", "nonsense", "120", "-1s", "1us", "1.0001ms", "2147483648ms", "999999999999999999999999s",
		"0.1ns", "-0.1ns", "-0.0000000001s", "1ms0.1ns", "1.0000001ms", "500us499.9999999us", "2147483647ms0.1ns",
	} {
		t.Run(invalid, func(t *testing.T) {
			original := 2 * time.Minute
			m := &model.Model{HTTP: []model.HTTPListener{{Routes: []model.HTTPRoute{{Backends: []model.Backend{
				{Namespace: "default", Name: "valid", TCPUserTimeout: &original},
				{Namespace: "default", Name: "invalid", TCPUserTimeout: &original},
			}}}}}}
			services := []corev1.Service{
				{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "valid", Annotations: map[string]string{annotation.ServiceUpstreamTCPUserTimeout: "60s"}}},
				{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "invalid", Annotations: map[string]string{annotation.ServiceUpstreamTCPUserTimeout: invalid}}},
			}
			err := ApplyBackendTCPUserTimeouts(m, services)
			require.ErrorContains(t, err, "Service default/invalid")
			require.ErrorContains(t, err, annotation.ServiceUpstreamTCPUserTimeout)
			for be := range m.HTTPBackends() {
				require.Equal(t, &original, be.TCPUserTimeout)
			}
		})
	}
}
