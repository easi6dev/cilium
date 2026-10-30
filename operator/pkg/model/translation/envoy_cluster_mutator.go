// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_upstreams_http_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
)

type ClusterMutator func(*envoy_config_cluster_v3.Cluster) *envoy_config_cluster_v3.Cluster

// Linux UAPI values: these configure Envoy's Linux sockets even when the
// operator or its unit tests are built on another operating system.
const (
	tcpSocketOptionLevel       = 6  // IPPROTO_TCP
	tcpUserTimeoutSocketOption = 18 // TCP_USER_TIMEOUT
)

// withClusterLbPolicy sets the cluster's load balancing policy.
// https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/load_balancing/load_balancers
func withClusterLbPolicy(lbPolicy int32) ClusterMutator {
	return func(cluster *envoy_config_cluster_v3.Cluster) *envoy_config_cluster_v3.Cluster {
		if cluster == nil {
			return cluster
		}
		cluster.LbPolicy = envoy_config_cluster_v3.Cluster_LbPolicy(lbPolicy)
		return cluster
	}
}

// withOutlierDetection enables outlier detection on the cluster.
func withOutlierDetection(splitExternalLocalOriginErrors bool) ClusterMutator {
	return func(cluster *envoy_config_cluster_v3.Cluster) *envoy_config_cluster_v3.Cluster {
		if cluster == nil {
			return cluster
		}
		cluster.OutlierDetection = &envoy_config_cluster_v3.OutlierDetection{
			SplitExternalLocalOriginErrors: splitExternalLocalOriginErrors,
		}
		return cluster
	}
}

// withConnectionTimeout sets the cluster's connection timeout.
func withConnectionTimeout(seconds int) ClusterMutator {
	return func(cluster *envoy_config_cluster_v3.Cluster) *envoy_config_cluster_v3.Cluster {
		if cluster == nil {
			return cluster
		}
		cluster.ConnectTimeout = &durationpb.Duration{Seconds: int64(seconds)}
		return cluster
	}
}

// withTCPUserTimeout bounds how long an upstream TCP socket may keep
// unacknowledged data before the kernel closes it. TCP_USER_TIMEOUT is a Linux
// socket option whose value is expressed in milliseconds.
func withTCPUserTimeout(milliseconds int64) ClusterMutator {
	return func(cluster *envoy_config_cluster_v3.Cluster) *envoy_config_cluster_v3.Cluster {
		if cluster == nil || milliseconds <= 0 {
			return cluster
		}

		if cluster.UpstreamBindConfig == nil {
			cluster.UpstreamBindConfig = &envoy_config_core_v3.BindConfig{}
		}
		option := &envoy_config_core_v3.SocketOption{
			Description: "TCP_USER_TIMEOUT for stalled upstream connections",
			Level:       tcpSocketOptionLevel,
			Name:        tcpUserTimeoutSocketOption,
			Value: &envoy_config_core_v3.SocketOption_IntValue{
				IntValue: milliseconds,
			},
			State: envoy_config_core_v3.SocketOption_STATE_PREBIND,
			Type: &envoy_config_core_v3.SocketOption_SocketType{
				Stream: &envoy_config_core_v3.SocketOption_SocketType_Stream{},
			},
		}
		// Replace this option rather than appending duplicate PREBIND settings.
		options := cluster.UpstreamBindConfig.SocketOptions[:0]
		for _, existing := range cluster.UpstreamBindConfig.SocketOptions {
			if existing.GetLevel() == tcpSocketOptionLevel && existing.GetName() == tcpUserTimeoutSocketOption && existing.GetState() == envoy_config_core_v3.SocketOption_STATE_PREBIND {
				continue
			}
			options = append(options, existing)
		}
		cluster.UpstreamBindConfig.SocketOptions = append(options, option)

		return cluster
	}
}

// withIdleTimeout sets the cluster's connection idle timeout.
func withIdleTimeout(seconds int) ClusterMutator {
	return func(cluster *envoy_config_cluster_v3.Cluster) *envoy_config_cluster_v3.Cluster {
		if cluster == nil {
			return cluster
		}
		a := cluster.TypedExtensionProtocolOptions[httpProtocolOptionsType]
		opts := &envoy_upstreams_http_v3.HttpProtocolOptions{}
		if err := a.UnmarshalTo(opts); err != nil {
			return cluster
		}
		opts.CommonHttpProtocolOptions = &envoy_config_core_v3.HttpProtocolOptions{
			IdleTimeout: &durationpb.Duration{Seconds: int64(seconds)},
		}
		cluster.TypedExtensionProtocolOptions[httpProtocolOptionsType] = toAny(opts)
		return cluster
	}
}

func withProtocol(protocolVersion HTTPVersionType) ClusterMutator {
	return func(cluster *envoy_config_cluster_v3.Cluster) *envoy_config_cluster_v3.Cluster {
		a := cluster.TypedExtensionProtocolOptions[httpProtocolOptionsType]
		options := &envoy_upstreams_http_v3.HttpProtocolOptions{}
		if err := a.UnmarshalTo(options); err != nil {
			return cluster
		}
		switch protocolVersion {
		// Default protocol version in Envoy is HTTP1.1.
		case HTTPVersion1, HTTPVersionAuto:
			options.UpstreamProtocolOptions = &envoy_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_{
				ExplicitHttpConfig: &envoy_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig{
					ProtocolConfig: &envoy_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_HttpProtocolOptions{},
				},
			}
		case HTTPVersion2:
			options.UpstreamProtocolOptions = &envoy_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_{
				ExplicitHttpConfig: &envoy_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig{
					ProtocolConfig: &envoy_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_Http2ProtocolOptions{},
				},
			}
		case HTTPVersion3:
			options.UpstreamProtocolOptions = &envoy_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_{
				ExplicitHttpConfig: &envoy_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig{
					ProtocolConfig: &envoy_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_Http3ProtocolOptions{},
				},
			}
		}

		cluster.TypedExtensionProtocolOptions = map[string]*anypb.Any{
			httpProtocolOptionsType: toAny(options),
		}
		return cluster
	}
}
