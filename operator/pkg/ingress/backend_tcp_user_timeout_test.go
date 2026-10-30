// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/cilium/cilium/operator/pkg/model/translation"
	ingressTranslation "github.com/cilium/cilium/operator/pkg/model/translation/ingress"
	"github.com/cilium/cilium/pkg/annotation"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func TestIngressBackendTCPUserTimeoutReconcile(t *testing.T) {
	// Production registers this comparator in controller-runtime.newManager.
	// The fake client bypasses that initialization, but repeated reconciliation
	// still uses CreateOrUpdate's semantic comparison of CEC protobuf resources.
	originalEqualities := equality.Semantic
	equality.Semantic = equality.Semantic.Copy()
	t.Cleanup(func() { equality.Semantic = originalEqualities })
	require.NoError(t, equality.Semantic.AddFunc(func(a, b ciliumv2.XDSResource) bool {
		return proto.Equal(a.Any, b.Any)
	}))

	for _, mode := range []string{"shared", "dedicated"} {
		t.Run(mode, func(t *testing.T) {
			logger := hivetest.Logger(t)
			ingress := &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test", Name: "test"},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr.To("cilium"),
					DefaultBackend:   defaultBackend(),
					Rules: []networkingv1.IngressRule{{
						IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{{
								Path: "/path", PathType: ptr.To(networkingv1.PathTypePrefix),
								Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{
									Name: "path", Port: networkingv1.ServiceBackendPort{Number: 8080},
								}},
							}},
						}},
					}},
				},
			}
			fakeClient := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(ingress,
				&corev1.Service{ObjectMeta: metav1.ObjectMeta{
					Namespace: "test", Name: "path",
					Annotations: map[string]string{annotation.ServiceUpstreamTCPUserTimeout: "300s"},
				}},
				// Invalid configuration on an unrelated Service must not block reconciliation.
				&corev1.Service{ObjectMeta: metav1.ObjectMeta{
					Namespace: "test", Name: "unrelated",
					Annotations: map[string]string{annotation.ServiceUpstreamTCPUserTimeout: "invalid"},
				}},
			).Build()
			cecTranslator := translation.NewCECTranslator(translation.Config{
				ClusterConfig: translation.ClusterConfig{UpstreamTCPUserTimeoutSeconds: 120},
			})
			r := newIngressReconciler(logger, fakeClient, cecTranslator,
				ingressTranslation.NewDedicatedIngressTranslator(logger, cecTranslator, false),
				testCiliumNamespace, nil, testDefaultLoadbalancingServiceName, mode,
				"", "", false, 0, false, 0)
			request := reconcile.Request{NamespacedName: client.ObjectKeyFromObject(ingress)}
			cecKey := types.NamespacedName{Namespace: testCiliumNamespace, Name: testDefaultLoadbalancingServiceName}
			if mode == "dedicated" {
				cecKey = types.NamespacedName{Namespace: "test", Name: "cilium-ingress-test-test"}
			}
			checkTimeout := func(expected *int64) {
				t.Helper()
				_, err := r.Reconcile(t.Context(), request)
				require.NoError(t, err)
				var cec ciliumv2.CiliumEnvoyConfig
				require.NoError(t, fakeClient.Get(t.Context(), cecKey, &cec))
				require.Equal(t, expected, ingressClusterTCPUserTimeout(t, &cec, "test:test:8080"))
				require.Equal(t, ptr.To(int64(300000)), ingressClusterTCPUserTimeout(t, &cec, "test:path:8080"))
			}

			// Missing Services retain the global default, as do Services without an override.
			checkTimeout(ptr.To(int64(120000)))
			service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "test", Name: "test"}}
			require.NoError(t, fakeClient.Create(t.Context(), service))
			checkTimeout(ptr.To(int64(120000)))
			service.Annotations = map[string]string{annotation.ServiceUpstreamTCPUserTimeout: "60s"}
			require.NoError(t, fakeClient.Update(t.Context(), service))
			checkTimeout(ptr.To(int64(60000)))
			service.Annotations[annotation.ServiceUpstreamTCPUserTimeout] = "90s"
			require.NoError(t, fakeClient.Update(t.Context(), service))
			checkTimeout(ptr.To(int64(90000)))
			delete(service.Annotations, annotation.ServiceUpstreamTCPUserTimeout)
			require.NoError(t, fakeClient.Update(t.Context(), service))
			checkTimeout(ptr.To(int64(120000)))
			service.Annotations = map[string]string{annotation.ServiceUpstreamTCPUserTimeout: "0s"}
			require.NoError(t, fakeClient.Update(t.Context(), service))
			checkTimeout(nil)

			var before ciliumv2.CiliumEnvoyConfig
			require.NoError(t, fakeClient.Get(t.Context(), cecKey, &before))
			service.Annotations[annotation.ServiceUpstreamTCPUserTimeout] = "invalid"
			require.NoError(t, fakeClient.Update(t.Context(), service))
			_, err := r.Reconcile(t.Context(), request)
			require.Error(t, err)
			require.Contains(t, err.Error(), "test/test")
			var after ciliumv2.CiliumEnvoyConfig
			require.NoError(t, fakeClient.Get(t.Context(), cecKey, &after))
			require.Equal(t, before.Spec, after.Spec, "invalid overrides must preserve the last valid CEC")

			require.NoError(t, fakeClient.Delete(t.Context(), service))
			checkTimeout(ptr.To(int64(120000)))
		})
	}
}

func ingressClusterTCPUserTimeout(t *testing.T, cec *ciliumv2.CiliumEnvoyConfig, name string) *int64 {
	t.Helper()
	for _, resource := range cec.Spec.Resources {
		cluster := &clusterv3.Cluster{}
		if !resource.MessageIs(cluster) {
			continue
		}
		require.NoError(t, resource.UnmarshalTo(cluster))
		if cluster.Name != name {
			continue
		}
		for _, option := range cluster.GetUpstreamBindConfig().GetSocketOptions() {
			if option.Level == 6 && option.Name == 18 {
				return ptr.To(option.GetIntValue())
			}
		}
		return nil
	}
	t.Fatalf("cluster %q not found", name)
	return nil
}

func TestEnqueueIngressesForBackendService(t *testing.T) {
	newIngress := func(name, namespace, class, backend string, defaultBackend bool) *networkingv1.Ingress {
		i := &networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
			Spec:       networkingv1.IngressSpec{IngressClassName: ptr.To(class)},
		}
		b := networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: backend}}
		if defaultBackend {
			i.Spec.DefaultBackend = &b
		} else {
			i.Spec.Rules = []networkingv1.IngressRule{{
				IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
					Paths: []networkingv1.HTTPIngressPath{{Backend: b}, {Backend: b}},
				}},
			}}
		}
		return i
	}
	c := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(
		newIngress("default", "test", "cilium", "backend", true),
		newIngress("paths", "test", "cilium", "backend", false),
		newIngress("unrelated", "test", "cilium", "other", true),
		newIngress("foreign", "test", "nginx", "backend", false),
		newIngress("other-namespace", "other", "cilium", "backend", true),
	).Build()
	r := &ingressReconciler{client: c, logger: hivetest.Logger(t)}
	requests := r.enqueueIngressesForBackendService(t.Context(), &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "test", Name: "backend"},
	})
	require.ElementsMatch(t, []reconcile.Request{
		{NamespacedName: types.NamespacedName{Namespace: "test", Name: "default"}},
		{NamespacedName: types.NamespacedName{Namespace: "test", Name: "paths"}},
	}, requests)
}

func TestBackendTCPUserTimeoutChanged(t *testing.T) {
	service := func(value *string) *corev1.Service {
		s := &corev1.Service{}
		if value != nil {
			s.Annotations = map[string]string{annotation.ServiceUpstreamTCPUserTimeout: *value}
		}
		return s
	}
	p := backendTCPUserTimeoutChanged()
	for _, tt := range []struct {
		name       string
		old, next  *string
		wantUpdate bool
	}{
		{name: "absent"},
		{name: "added", next: ptr.To("60s"), wantUpdate: true},
		{name: "changed", old: ptr.To("60s"), next: ptr.To("90s"), wantUpdate: true},
		{name: "removed", old: ptr.To("60s"), wantUpdate: true},
		{name: "unchanged", old: ptr.To("60s"), next: ptr.To("60s")},
		{name: "empty annotation added", next: ptr.To(""), wantUpdate: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.wantUpdate, p.Update(event.UpdateEvent{ObjectOld: service(tt.old), ObjectNew: service(tt.next)}))
		})
	}
	require.True(t, p.Create(event.CreateEvent{Object: service(ptr.To("60s"))}))
	require.True(t, p.Delete(event.DeleteEvent{Object: service(ptr.To("0s"))}))
	require.False(t, p.Create(event.CreateEvent{Object: service(nil)}))
	require.False(t, p.Delete(event.DeleteEvent{Object: service(nil)}))
}
