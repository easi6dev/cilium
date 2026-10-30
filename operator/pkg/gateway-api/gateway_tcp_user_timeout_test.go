// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	"github.com/cilium/cilium/operator/pkg/model/translation"
	gatewayApiTranslation "github.com/cilium/cilium/operator/pkg/model/translation/gateway-api"
	"github.com/cilium/cilium/pkg/annotation"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func TestGatewayBackendTCPUserTimeoutReconcile(t *testing.T) {
	logger := hivetest.Logger(t)
	config := translation.Config{
		ClusterConfig: translation.ClusterConfig{IdleTimeoutSeconds: 60, UpstreamTCPUserTimeoutSeconds: 120},
		ServiceConfig: translation.ServiceConfig{ExternalTrafficPolicy: string(corev1.ServiceExternalTrafficPolicyCluster)},
	}
	scheme := testScheme()
	objects := append(readInputDir(t, "testdata/gateway/base"), readInputDir(t, "testdata/gateway/httproute-simple-same-namespace/input")...)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).
		WithIndex(&gatewayv1.HTTPRoute{}, gatewayHTTPRouteIndex, indexers.IndexHTTPRouteByGateway).
		WithIndex(&gatewayv1.GRPCRoute{}, gatewayGRPCRouteIndex, indexers.IndexGRPCRouteByGateway).
		WithIndex(&gatewayv1alpha2.TLSRoute{}, gatewayTLSRouteIndex, indexers.IndexTLSRouteByGateway).
		WithStatusSubresource(&corev1.Service{}, &corev1.Namespace{}, &gatewayv1.HTTPRoute{}, &gatewayv1.GRPCRoute{}, &gatewayv1alpha2.TLSRoute{}, &gatewayv1.Gateway{}, &gatewayv1.GatewayClass{}).
		WithInterceptorFuncs(typeMetaInterceptor(scheme)).Build()
	r := &gatewayReconciler{Client: c, logger: logger, translator: gatewayApiTranslation.NewTranslator(translation.NewCECTranslator(config), config)}
	parentKey := client.ObjectKey{Namespace: "gateway-conformance-infra", Name: "same-namespace"}
	cecKey := client.ObjectKey{Namespace: parentKey.Namespace, Name: "cilium-gateway-same-namespace"}
	backendKey := client.ObjectKey{Namespace: parentKey.Namespace, Name: "infra-backend-v1"}
	var previous *ciliumv2.CiliumEnvoyConfig
	for _, step := range []struct {
		name    string
		value   string
		want    int64
		wantErr bool
	}{
		{name: "override", value: "60s", want: 60000},
		{name: "invalid-keeps-last-config", value: "-1s", want: 60000, wantErr: true},
		{name: "remove", want: 120000},
	} {
		t.Run(step.name, func(t *testing.T) {
			backend := &corev1.Service{}
			require.NoError(t, c.Get(t.Context(), backendKey, backend))
			backend.Annotations = map[string]string{}
			if step.value != "" {
				backend.Annotations[annotation.ServiceUpstreamTCPUserTimeout] = step.value
			}
			require.NoError(t, c.Update(t.Context(), backend))
			_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: parentKey})
			if step.wantErr {
				require.ErrorContains(t, err, annotation.ServiceUpstreamTCPUserTimeout)
			} else {
				require.NoError(t, err)
			}
			cec := &ciliumv2.CiliumEnvoyConfig{}
			require.NoError(t, c.Get(t.Context(), cecKey, cec))
			assertClusterTCPUserTimeout(t, cec, backendKey.Namespace+":"+backendKey.Name+":8080", step.want)
			if step.wantErr {
				require.Equal(t, previous.Spec, cec.Spec)
				require.Equal(t, previous.ResourceVersion, cec.ResourceVersion)
				parent := &gatewayv1.Gateway{}
				require.NoError(t, c.Get(t.Context(), parentKey, parent))
				condition := meta.FindStatusCondition(parent.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
				require.NotNil(t, condition)
				require.Equal(t, metav1.ConditionFalse, condition.Status)
				require.Contains(t, condition.Message, annotation.ServiceUpstreamTCPUserTimeout)
			}
			previous = cec
		})
	}
}

func TestGatewayBackendServiceWithoutTLSRoute(t *testing.T) {
	// TLSRoute is optional: a missing CRD must not prevent HTTP/GRPC backend
	// annotation changes from reaching their Gateway.
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, registerGatewayAPITypesToScheme(scheme, nil))
	logger := hivetest.Logger(t)
	parent := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "test"}, Spec: gatewayv1.GatewaySpec{GatewayClassName: "cilium"}}
	class := &gatewayv1.GatewayClass{ObjectMeta: metav1.ObjectMeta{Name: "cilium"}, Spec: gatewayv1.GatewayClassSpec{ControllerName: controllerName}}
	backend := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "backend", Namespace: "test"}}
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: "test"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway"}}},
			Rules:           []gatewayv1.HTTPRouteRule{{BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: ptr.To(gatewayv1.PortNumber(8080))}}}}}},
		},
	}
	baseClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(class).Build()
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(class, parent, backend, route).
		WithIndex(&gatewayv1.HTTPRoute{}, backendServiceHTTPRouteIndex, indexers.GenerateIndexerHTTPRouteByBackendService(baseClient, logger)).
		WithIndex(&gatewayv1.GRPCRoute{}, backendServiceGRPCRouteIndex, indexers.GenerateIndexerGRPCRoutebyBackendService(baseClient, logger)).
		WithIndex(&gatewayv1.Gateway{}, implementationGatewayIndex, indexers.GenerateIndexerGatewayByImplementation(baseClient, controllerName)).Build()
	r := &gatewayReconciler{Client: c, logger: logger}
	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	defer queue.ShutDown()
	updated := backend.DeepCopy()
	updated.Annotations = map[string]string{annotation.ServiceUpstreamTCPUserTimeout: "60s"}
	r.enqueueRequestForBackendService().Update(t.Context(), event.UpdateEvent{ObjectOld: backend, ObjectNew: updated}, queue)
	require.Equal(t, 1, queue.Len())
	request, shutdown := queue.Get()
	require.False(t, shutdown)
	defer queue.Done(request)
	require.Equal(t, client.ObjectKeyFromObject(parent), request.NamespacedName)
}
