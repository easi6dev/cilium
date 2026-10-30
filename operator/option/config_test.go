// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	daemonoption "github.com/cilium/cilium/pkg/option"
)

func TestUpstreamTCPUserTimeoutConfig(t *testing.T) {
	for _, tt := range []struct {
		name    string
		seconds int
		invalid bool
	}{
		{name: "disabled"},
		{name: "enabled", seconds: 120},
		{name: "maximum", seconds: MaxProxyUpstreamTCPUserTimeoutSeconds},
		{name: "negative", seconds: -1, invalid: true},
		{name: "overflow", seconds: MaxProxyUpstreamTCPUserTimeoutSeconds + 1, invalid: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			vp := viper.New()
			vp.Set(ProxyUpstreamTCPUserTimeoutSeconds, tt.seconds)
			cfg := &OperatorConfig{}
			cfg.Populate(hivetest.Logger(t), vp)
			require.Equal(t, tt.seconds, cfg.ProxyUpstreamTCPUserTimeoutSeconds)
			if tt.invalid {
				require.ErrorContains(t, cfg.ValidateUpstreamTCPUserTimeout(), ProxyUpstreamTCPUserTimeoutSeconds)
			} else {
				require.NoError(t, cfg.ValidateUpstreamTCPUserTimeout())
			}
		})
	}
}

func TestUpstreamTCPUserTimeoutDefaultDisabled(t *testing.T) {
	cfg := &OperatorConfig{}
	cfg.Populate(hivetest.Logger(t), viper.New())
	require.Zero(t, cfg.ProxyUpstreamTCPUserTimeoutSeconds)
	require.NoError(t, cfg.ValidateUpstreamTCPUserTimeout())
}

func TestUpstreamTCPUserTimeoutEnvironment(t *testing.T) {
	for _, value := range []string{"0", "120"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("CILIUM_PROXY_UPSTREAM_TCP_USER_TIMEOUT_SECONDS", value)
			vp := viper.New()
			daemonoption.BindEnv(vp, ProxyUpstreamTCPUserTimeoutSeconds)
			cfg := &OperatorConfig{}
			cfg.Populate(hivetest.Logger(t), vp)
			require.Equal(t, vp.GetInt(ProxyUpstreamTCPUserTimeoutSeconds), cfg.ProxyUpstreamTCPUserTimeoutSeconds)
			require.NoError(t, cfg.ValidateUpstreamTCPUserTimeout())
		})
	}
}
