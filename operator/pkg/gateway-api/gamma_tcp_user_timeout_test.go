// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"fmt"
	"testing"

	"github.com/cilium/hive/hivetest"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	"github.com/cilium/cilium/operator/pkg/model/translation"
	gatewayApiTranslation "github.com/cilium/cilium/operator/pkg/model/translation/gateway-api"
	"github.com/cilium/cilium/pkg/annotation"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func TestGammaBackendServiceEnqueuesParents(t *testing.T) {
	for _, protocol := range []string{"http", "grpc"} {
		for _, location := range []string{"backend", "rule-mirror", "backend-mirror"} {
			for _, crossNamespace := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/cross-namespace=%t", protocol, location, crossNamespace), func(t *testing.T) {
					logger := hivetest.Logger(t)
					parent := &corev1.Service{
						ObjectMeta: metav1.ObjectMeta{Name: "frontend", Namespace: "routes"},
						Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP},
					}
					backend := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "backend", Namespace: "routes"}}
					ref := gatewayv1.BackendObjectReference{Name: "backend", Port: ptr.To(gatewayv1.PortNumber(8080))}
					if crossNamespace {
						backend.Namespace = "backends"
						ref.Namespace = ptr.To(gatewayv1.Namespace(backend.Namespace))
					}
					parentRef := gatewayv1.ParentReference{Group: ptr.To(gatewayv1.Group("")), Kind: ptr.To(gatewayv1.Kind("Service")), Name: "frontend"}
					// Multiple references to the same parent must enqueue it only once.
					common := gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{
						parentRef, parentRef,
						{Name: "gateway"},
						{Group: ptr.To(gatewayv1.Group("")), Kind: ptr.To(gatewayv1.Kind("Secret")), Name: "unrelated"},
					}}
					mirror := &gatewayv1.HTTPRequestMirrorFilter{BackendRef: ref}
					objMeta := metav1.ObjectMeta{Name: "route", Namespace: "routes"}
					var route client.Object
					if protocol == "http" {
						rule := gatewayv1.HTTPRouteRule{}
						filter := gatewayv1.HTTPRouteFilter{Type: gatewayv1.HTTPRouteFilterRequestMirror, RequestMirror: mirror}
						switch location {
						case "backend":
							rule.BackendRefs = []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: ref}}}
						case "rule-mirror":
							rule.Filters = []gatewayv1.HTTPRouteFilter{filter}
						case "backend-mirror":
							rule.BackendRefs = []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "primary"}}, Filters: []gatewayv1.HTTPRouteFilter{filter}}}
						}
						route = &gatewayv1.HTTPRoute{ObjectMeta: objMeta, Spec: gatewayv1.HTTPRouteSpec{CommonRouteSpec: common, Rules: []gatewayv1.HTTPRouteRule{rule}}}
					} else {
						rule := gatewayv1.GRPCRouteRule{}
						filter := gatewayv1.GRPCRouteFilter{Type: gatewayv1.GRPCRouteFilterRequestMirror, RequestMirror: mirror}
						switch location {
						case "backend":
							rule.BackendRefs = []gatewayv1.GRPCBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: ref}}}
						case "rule-mirror":
							rule.Filters = []gatewayv1.GRPCRouteFilter{filter}
						case "backend-mirror":
							rule.BackendRefs = []gatewayv1.GRPCBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "primary"}}, Filters: []gatewayv1.GRPCRouteFilter{filter}}}
						}
						route = &gatewayv1.GRPCRoute{ObjectMeta: objMeta, Spec: gatewayv1.GRPCRouteSpec{CommonRouteSpec: common, Rules: []gatewayv1.GRPCRouteRule{rule}}}
					}
					unrelated := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Namespace: "routes"}, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP}}
					baseClient := fake.NewClientBuilder().WithScheme(testScheme()).Build()
					c := fake.NewClientBuilder().WithScheme(testScheme()).
						WithObjects(parent, backend, unrelated, route).
						WithIndex(&gatewayv1.HTTPRoute{}, backendServiceHTTPRouteIndex, indexers.GenerateIndexerHTTPRouteByBackendService(baseClient, logger)).
						WithIndex(&gatewayv1.GRPCRoute{}, backendServiceGRPCRouteIndex, indexers.GenerateIndexerGRPCRoutebyBackendService(baseClient, logger)).Build()
					r := &gammaReconciler{Client: c, logger: logger}
					require.Equal(t, []reconcile.Request{{NamespacedName: client.ObjectKeyFromObject(parent)}}, r.enqueueForBackendService()(t.Context(), backend))
					require.Empty(t, r.enqueueForBackendService()(t.Context(), unrelated))
				})
			}
		}
	}
}

func TestGammaBackendTCPUserTimeoutReconcile(t *testing.T) {
	for _, fixture := range []struct {
		name string
		port int
	}{
		{name: "mesh-basic", port: 8080},
		{name: "mesh-grpc-weight", port: 7070},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			logger := hivetest.Logger(t)
			config := translation.Config{
				ClusterConfig: translation.ClusterConfig{IdleTimeoutSeconds: 60, UpstreamTCPUserTimeoutSeconds: 120},
				ServiceConfig: translation.ServiceConfig{ExternalTrafficPolicy: string(corev1.ServiceExternalTrafficPolicyCluster)},
			}
			translator := gatewayApiTranslation.NewTranslator(translation.NewCECTranslator(config), config)
			scheme := testScheme()
			objects := append(readInputDir(t, "testdata/gamma/base"), readInputDir(t, "testdata/gamma/"+fixture.name+"/input")...)
			c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).
				WithIndex(&gatewayv1.HTTPRoute{}, gammaHTTPRouteParentRefsIndex, indexers.IndexHTTPRouteByGammaService).
				WithIndex(&gatewayv1.GRPCRoute{}, gammaGRPCRouteParentRefsIndex, indexers.IndexGRPCRouteByGammaService).
				WithStatusSubresource(&corev1.Service{}, &gatewayv1.HTTPRoute{}, &gatewayv1.GRPCRoute{}).
				WithInterceptorFuncs(typeMetaInterceptor(scheme)).Build()
			r := &gammaReconciler{Client: c, translator: translator, logger: logger}
			clusterName := fmt.Sprintf("%s:%s:%d", serviceKeyEchoV1.Namespace, serviceKeyEchoV1.Name, fixture.port)
			var previous *ciliumv2.CiliumEnvoyConfig
			for _, step := range []struct {
				name    string
				value   *string
				want    int64
				wantErr bool
			}{
				{name: "inherit", want: 120000},
				{name: "add", value: ptr.To("60s"), want: 60000},
				{name: "change", value: ptr.To("5m"), want: 300000},
				{name: "disable", value: ptr.To("0s"), want: 0},
				{name: "remove", want: 120000},
				{name: "invalid-keeps-last-config", value: ptr.To("invalid"), want: 120000, wantErr: true},
				{name: "recover", value: ptr.To("90s"), want: 90000},
			} {
				t.Run(step.name, func(t *testing.T) {
					backend := &corev1.Service{}
					require.NoError(t, c.Get(t.Context(), serviceKeyEchoV1, backend))
					if backend.Annotations == nil {
						backend.Annotations = map[string]string{}
					}
					if step.value == nil {
						delete(backend.Annotations, annotation.ServiceUpstreamTCPUserTimeout)
					} else {
						backend.Annotations[annotation.ServiceUpstreamTCPUserTimeout] = *step.value
					}
					require.NoError(t, c.Update(t.Context(), backend))
					_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: serviceKeyEcho})
					if step.wantErr {
						require.ErrorContains(t, err, annotation.ServiceUpstreamTCPUserTimeout)
					} else {
						require.NoError(t, err)
					}
					cec := &ciliumv2.CiliumEnvoyConfig{}
					require.NoError(t, c.Get(t.Context(), serviceKeyEcho, cec))
					assertClusterTCPUserTimeout(t, cec, clusterName, step.want)
					if fixture.name == "mesh-grpc-weight" {
						assertClusterTCPUserTimeout(t, cec, fmt.Sprintf("%s:%s:%d", serviceKeyEchoV2.Namespace, serviceKeyEchoV2.Name, fixture.port), 120000)
					}
					parent := &corev1.Service{}
					require.NoError(t, c.Get(t.Context(), serviceKeyEcho, parent))
					condition := meta.FindStatusCondition(parent.Status.Conditions, CiliumGammaConditionProgrammed)
					require.NotNil(t, condition)
					if step.wantErr {
						require.Equal(t, previous.Spec, cec.Spec)
						require.Equal(t, previous.ResourceVersion, cec.ResourceVersion)
						require.Equal(t, metav1.ConditionFalse, condition.Status)
						require.Equal(t, "InvalidBackendConfiguration", condition.Reason)
					} else {
						require.Equal(t, metav1.ConditionTrue, condition.Status)
					}
					previous = cec
				})
			}
		})
	}
}

func TestBackendTCPUserTimeoutChanged(t *testing.T) {
	predicate := backendTCPUserTimeoutChanged()
	for _, tt := range []struct {
		name     string
		oldValue *string
		newValue *string
		want     bool
	}{
		{name: "add", newValue: ptr.To("60s"), want: true},
		{name: "change", oldValue: ptr.To("60s"), newValue: ptr.To("90s"), want: true},
		{name: "disable", oldValue: ptr.To("60s"), newValue: ptr.To("0s"), want: true},
		{name: "remove", oldValue: ptr.To("60s"), want: true},
		{name: "invalid-empty", newValue: ptr.To(""), want: true},
		{name: "unchanged", oldValue: ptr.To("60s"), newValue: ptr.To("60s")},
		{name: "absent"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			oldService := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}}}
			newService := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{"unrelated": "changed"}}}
			if tt.oldValue != nil {
				oldService.Annotations[annotation.ServiceUpstreamTCPUserTimeout] = *tt.oldValue
			}
			if tt.newValue != nil {
				newService.Annotations[annotation.ServiceUpstreamTCPUserTimeout] = *tt.newValue
			}
			newService.Status.Conditions = []metav1.Condition{{Type: CiliumGammaConditionProgrammed, Status: metav1.ConditionTrue}}
			require.Equal(t, tt.want, predicate.Update(event.UpdateEvent{ObjectOld: oldService, ObjectNew: newService}))
		})
	}
	require.True(t, predicate.Create(event.CreateEvent{Object: &corev1.Service{}}))
	require.True(t, predicate.Delete(event.DeleteEvent{Object: &corev1.Service{}}))
}

func assertClusterTCPUserTimeout(t *testing.T, cec *ciliumv2.CiliumEnvoyConfig, name string, milliseconds int64) {
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
		found := 0
		for _, option := range cluster.GetUpstreamBindConfig().GetSocketOptions() {
			if option.Level == 6 && option.Name == 18 {
				found++
				require.Equal(t, milliseconds, option.GetIntValue())
			}
		}
		if milliseconds == 0 {
			require.Zero(t, found)
		} else {
			require.Equal(t, 1, found)
		}
		return
	}
	t.Fatalf("cluster %q not found", name)
}
