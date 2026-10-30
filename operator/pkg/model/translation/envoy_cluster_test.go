// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"syscall"
	"testing"
	"time"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/operator/pkg/model"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func Test_withClusterLbPolicy(t *testing.T) {
	fn := withClusterLbPolicy(int32(envoy_config_cluster_v3.Cluster_LEAST_REQUEST))

	t.Run("input is nil", func(t *testing.T) {
		cluster := fn(nil)
		require.Nil(t, cluster)
	})

	t.Run("input is not nil", func(t *testing.T) {
		cluster := &envoy_config_cluster_v3.Cluster{}
		cluster = fn(cluster)
		require.Equal(t, envoy_config_cluster_v3.Cluster_LEAST_REQUEST, cluster.LbPolicy)
	})
}

func Test_withOutlierDetection(t *testing.T) {
	t.Run("input is nil", func(t *testing.T) {
		fn := withOutlierDetection(true)
		cluster := fn(nil)
		require.Nil(t, cluster)
	})

	t.Run("input is not nil", func(t *testing.T) {
		t.Run("enabled", func(t *testing.T) {
			fn := withOutlierDetection(true)
			cluster := &envoy_config_cluster_v3.Cluster{}
			cluster = fn(cluster)
			require.NotNil(t, cluster.OutlierDetection)
			require.True(t, cluster.OutlierDetection.SplitExternalLocalOriginErrors)
		})

		t.Run("disabled", func(t *testing.T) {
			fn := withOutlierDetection(false)
			cluster := &envoy_config_cluster_v3.Cluster{}
			cluster = fn(cluster)
			require.NotNil(t, cluster.OutlierDetection)
			require.False(t, cluster.OutlierDetection.SplitExternalLocalOriginErrors)
		})
	})
}

func Test_withConnectionTimeout(t *testing.T) {
	fn := withConnectionTimeout(10)

	t.Run("input is nil", func(t *testing.T) {
		cluster := fn(nil)
		require.Nil(t, cluster)
	})

	t.Run("input is not nil", func(t *testing.T) {
		cluster := &envoy_config_cluster_v3.Cluster{}
		cluster = fn(cluster)
		require.Equal(t, int64(10), cluster.ConnectTimeout.Seconds)
	})
}

func Test_withTCPUserTimeout(t *testing.T) {
	fn := withTCPUserTimeout(15_000)

	t.Run("input is nil", func(t *testing.T) {
		require.Nil(t, fn(nil))
	})

	t.Run("disabled", func(t *testing.T) {
		cluster := withTCPUserTimeout(0)(&envoy_config_cluster_v3.Cluster{})
		require.Nil(t, cluster.UpstreamBindConfig)
	})

	t.Run("preserves existing bind config", func(t *testing.T) {
		cluster := &envoy_config_cluster_v3.Cluster{
			UpstreamBindConfig: &envoy_config_core_v3.BindConfig{
				SourceAddress: &envoy_config_core_v3.SocketAddress{Address: "127.0.0.1"},
				SocketOptions: []*envoy_config_core_v3.SocketOption{
					{
						Description: "SO_KEEPALIVE",
						Level:       syscall.SOL_SOCKET,
						Name:        syscall.SO_KEEPALIVE,
						Value: &envoy_config_core_v3.SocketOption_IntValue{
							IntValue: 1,
						},
						State: envoy_config_core_v3.SocketOption_STATE_PREBIND,
					},
				},
			},
		}
		cluster = fn(cluster)

		require.Len(t, cluster.UpstreamBindConfig.SocketOptions, 2)
		require.Equal(t, int64(syscall.SO_KEEPALIVE), cluster.UpstreamBindConfig.SocketOptions[0].Name)
		option := cluster.UpstreamBindConfig.SocketOptions[1]
		require.Equal(t, int64(syscall.IPPROTO_TCP), option.Level)
		require.Equal(t, int64(tcpUserTimeoutSocketOption), option.Name)
		require.Equal(t, int64(15_000), option.GetIntValue())
		require.Equal(t, envoy_config_core_v3.SocketOption_STATE_PREBIND, option.State)
		require.NotNil(t, option.GetType().GetStream())
		require.Equal(t, "127.0.0.1", cluster.UpstreamBindConfig.SourceAddress.Address)

		// Repeated mutations and pre-existing duplicates must leave one value.
		cluster.UpstreamBindConfig.SocketOptions = append(cluster.UpstreamBindConfig.SocketOptions, proto.Clone(option).(*envoy_config_core_v3.SocketOption))
		cluster = withTCPUserTimeout(60_000)(cluster)
		cluster = withTCPUserTimeout(60_000)(cluster)
		require.Len(t, cluster.UpstreamBindConfig.SocketOptions, 2)
		require.Equal(t, int64(syscall.SO_KEEPALIVE), cluster.UpstreamBindConfig.SocketOptions[0].Name)
		require.Equal(t, int64(60_000), cluster.UpstreamBindConfig.SocketOptions[1].GetIntValue())
	})
}

func Test_httpCluster(t *testing.T) {
	c := &cecTranslator{}
	res, err := c.httpCluster("dummy-name", "dummy-name", false, "", 0)
	require.NoError(t, err)

	cluster := &envoy_config_cluster_v3.Cluster{}
	err = proto.Unmarshal(res.Value, cluster)

	require.NoError(t, err)
	require.Equal(t, "dummy-name", cluster.Name)
	require.Equal(t, &envoy_config_cluster_v3.Cluster_Type{
		Type: envoy_config_cluster_v3.Cluster_EDS,
	}, cluster.ClusterDiscoveryType)
}

func Test_desiredEnvoyClusterTCPUserTimeout(t *testing.T) {
	for _, grpc := range []bool{false, true} {
		for _, defaultSeconds := range []int{0, 120} {
			t.Run(fmt.Sprintf("grpc=%v/default=%d", grpc, defaultSeconds), func(t *testing.T) {
				off, minute := time.Duration(0), time.Minute
				c := &cecTranslator{Config: Config{ClusterConfig: ClusterConfig{UpstreamTCPUserTimeoutSeconds: defaultSeconds}}}
				backend := func(name string, timeout *time.Duration) model.Backend {
					return model.Backend{Name: name, Namespace: "default", Port: &model.BackendPort{Port: 8080}, TCPUserTimeout: timeout}
				}
				overridden := backend("override", &minute)
				m := &model.Model{
					HTTP: []model.HTTPListener{{Routes: []model.HTTPRoute{
						{IsGRPC: grpc, Backends: []model.Backend{backend("inherited", nil), overridden, backend("disabled", &off)}},
						{IsGRPC: grpc, Backends: []model.Backend{overridden}, RequestMirrors: []*model.HTTPRequestMirror{{Backend: ptr.To(backend("mirror", &minute))}}},
					}}},
					TLSPassthrough: []model.TLSPassthroughListener{{Routes: []model.TLSPassthroughRoute{{Backends: []model.Backend{backend("passthrough", &minute)}}}}},
				}
				resources, err := c.desiredEnvoyCluster(m)
				require.NoError(t, err)
				require.Len(t, resources, 5)
				expected := map[string]int64{"inherited": int64(defaultSeconds) * 1000, "override": 60000, "disabled": 0, "mirror": 60000, "passthrough": 0}
				for _, resource := range resources {
					cluster := &envoy_config_cluster_v3.Cluster{}
					require.NoError(t, proto.Unmarshal(resource.GetValue(), cluster))
					require.NoError(t, cluster.ValidateAll())
					name := strings.Split(cluster.Name, ":")[1]
					require.Equal(t, "default/"+name+":8080", cluster.GetEdsClusterConfig().GetServiceName())
					if expected[name] == 0 {
						require.Nil(t, cluster.UpstreamBindConfig)
					} else {
						require.NotNil(t, cluster.UpstreamBindConfig)
						require.Len(t, cluster.UpstreamBindConfig.SocketOptions, 1)
						option := cluster.UpstreamBindConfig.SocketOptions[0]
						require.Equal(t, int64(6), option.Level)
						require.Equal(t, int64(18), option.Name)
						require.Equal(t, expected[name], option.GetIntValue())
						require.Equal(t, envoy_config_core_v3.SocketOption_STATE_PREBIND, option.State)
						require.NotNil(t, option.GetType().GetStream())
					}
					data, err := json.Marshal(&resource)
					require.NoError(t, err)
					var restored ciliumv2.XDSResource
					require.NoError(t, json.Unmarshal(data, &restored))
					decoded := &envoy_config_cluster_v3.Cluster{}
					require.NoError(t, proto.Unmarshal(restored.GetValue(), decoded))
					require.True(t, proto.Equal(cluster, decoded))
				}
			})
		}
	}
}

func Test_desiredEnvoyClusterRejectsInvalidTCPUserTimeout(t *testing.T) {
	for _, seconds := range []int{-1, 2147484, math.MaxInt} {
		c := &cecTranslator{Config: Config{ClusterConfig: ClusterConfig{UpstreamTCPUserTimeoutSeconds: seconds}}}
		_, err := c.desiredEnvoyCluster(&model.Model{})
		require.ErrorContains(t, err, "upstream TCP user timeout seconds")
	}
	for _, timeout := range []time.Duration{-time.Second, time.Microsecond, model.MaxTCPUserTimeout + time.Millisecond} {
		c := &cecTranslator{}
		m := &model.Model{HTTP: []model.HTTPListener{{Routes: []model.HTTPRoute{{Backends: []model.Backend{{
			Namespace: "default", Name: "backend", Port: &model.BackendPort{Port: 8080}, TCPUserTimeout: &timeout,
		}}}}}}}
		_, err := c.desiredEnvoyCluster(m)
		require.ErrorContains(t, err, "cluster default:backend:8080")
	}
}

func Test_desiredEnvoyClusterRejectsConflictingTCPUserTimeouts(t *testing.T) {
	one, two := time.Minute, 2*time.Minute
	m := &model.Model{HTTP: []model.HTTPListener{{Routes: []model.HTTPRoute{
		{Backends: []model.Backend{{Namespace: "default", Name: "backend", Port: &model.BackendPort{Port: 8080}, TCPUserTimeout: &one}}},
		{Backends: []model.Backend{{Namespace: "default", Name: "backend", Port: &model.BackendPort{Port: 8080}, TCPUserTimeout: &two}}},
	}}}}
	_, err := (&cecTranslator{}).desiredEnvoyCluster(m)
	require.ErrorContains(t, err, "conflicting")
}

func Test_tcpCluster(t *testing.T) {
	c := &cecTranslator{}
	res, err := c.tcpCluster("dummy-name", "dummy-name")
	require.NoError(t, err)

	cluster := &envoy_config_cluster_v3.Cluster{}
	err = proto.Unmarshal(res.Value, cluster)

	require.NoError(t, err)
	require.Equal(t, "dummy-name", cluster.Name)
	require.Equal(t, &envoy_config_cluster_v3.Cluster_Type{
		Type: envoy_config_cluster_v3.Cluster_EDS,
	}, cluster.ClusterDiscoveryType)
}

func Test_desiredEnvoyClusterSharedHTTPAndTLSBackend(t *testing.T) {
	backend := model.Backend{Namespace: "default", Name: "shared", Port: &model.BackendPort{Port: 8080}}
	m := &model.Model{
		HTTP:           []model.HTTPListener{{Routes: []model.HTTPRoute{{Backends: []model.Backend{backend}}}}},
		TLSPassthrough: []model.TLSPassthroughListener{{Routes: []model.TLSPassthroughRoute{{Backends: []model.Backend{backend}}}}},
	}
	c := &cecTranslator{Config: Config{ClusterConfig: ClusterConfig{UpstreamTCPUserTimeoutSeconds: 120}}}
	_, err := c.desiredEnvoyCluster(m)
	require.ErrorContains(t, err, "shared by HTTP and TLS passthrough")
	// An explicit Service opt-out retains the existing passthrough behavior.
	m.HTTP[0].Routes[0].Backends[0].TCPUserTimeout = ptr.To(time.Duration(0))
	resources, err := c.desiredEnvoyCluster(m)
	require.NoError(t, err)
	require.Len(t, resources, 1)
	cluster := &envoy_config_cluster_v3.Cluster{}
	require.NoError(t, resources[0].UnmarshalTo(cluster))
	require.Nil(t, cluster.UpstreamBindConfig)
}
