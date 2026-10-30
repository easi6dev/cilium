// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/operator/pkg/model/ingestion"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func (r *ingressReconciler) applyBackendTCPUserTimeouts(ctx context.Context, m *model.Model) error {
	seen := make(map[types.NamespacedName]struct{})
	var services []corev1.Service
	for backend := range m.HTTPBackends() {
		key := types.NamespacedName{Namespace: backend.Namespace, Name: backend.Name}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		var service corev1.Service
		if err := r.client.Get(ctx, key, &service); err != nil {
			// Missing backends must retain the existing Ingress behavior. A Service
			// created later with an override triggers a new reconciliation.
			if k8serrors.IsNotFound(err) {
				continue
			}
			return fmt.Errorf("failed to get backend Service %s: %w", key, err)
		}
		services = append(services, service)
	}
	return ingestion.ApplyBackendTCPUserTimeouts(m, services)
}

func (r *ingressReconciler) enqueueIngressesForBackendService(ctx context.Context, obj client.Object) []reconcile.Request {
	var ingresses networkingv1.IngressList
	if err := r.client.List(ctx, &ingresses, client.InNamespace(obj.GetNamespace())); err != nil {
		r.logger.WarnContext(ctx, "Failed to list Ingresses for backend Service", logfields.Error, err)
		return nil
	}

	var requests []reconcile.Request
	for _, ingress := range ingresses.Items {
		if !ingressReferencesService(&ingress, obj.GetName()) || !isCiliumManagedIngress(ctx, r.client, r.logger, ingress) {
			continue
		}
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&ingress)})
	}
	return requests
}

func ingressReferencesService(ingress *networkingv1.Ingress, name string) bool {
	if backend := ingress.Spec.DefaultBackend; backend != nil && backend.Service != nil && backend.Service.Name == name {
		return true
	}
	for _, rule := range ingress.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for _, path := range rule.HTTP.Paths {
			if path.Backend.Service != nil && path.Backend.Service.Name == name {
				return true
			}
		}
	}
	return false
}

func backendTCPUserTimeoutChanged() predicate.Predicate {
	hasAnnotation := func(obj client.Object) bool {
		_, ok := obj.GetAnnotations()[annotation.ServiceUpstreamTCPUserTimeout]
		return ok
	}
	return predicate.Funcs{
		CreateFunc:  func(e event.CreateEvent) bool { return hasAnnotation(e.Object) },
		DeleteFunc:  func(e event.DeleteEvent) bool { return hasAnnotation(e.Object) },
		GenericFunc: func(e event.GenericEvent) bool { return hasAnnotation(e.Object) },
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldValue, oldPresent := e.ObjectOld.GetAnnotations()[annotation.ServiceUpstreamTCPUserTimeout]
			newValue, newPresent := e.ObjectNew.GetAnnotations()[annotation.ServiceUpstreamTCPUserTimeout]
			return oldPresent != newPresent || oldValue != newValue
		},
	}
}
