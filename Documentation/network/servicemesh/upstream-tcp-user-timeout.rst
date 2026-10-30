.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _upstream_tcp_user_timeout:

Upstream TCP User Timeout
=========================

Cilium can set Linux ``TCP_USER_TIMEOUT`` on the HTTP upstream connections that
the Operator generates for Gateway API, GAMMA, and Ingress. This bounds how long
transmitted data may remain unacknowledged, or buffered data may remain
untransmitted because the peer advertises a zero window, before the kernel closes
the connection. It can shorten recovery when an established upstream connection
becomes a network blackhole and would otherwise remain in Envoy's connection
pool until the kernel's normal TCP retry limit is reached.

This setting is disabled by default. It does not set an RPC deadline, change TCP
retransmission intervals, or actively probe an idle connection. It affects the
whole TCP connection, including all HTTP/2 streams sharing it. Configure gRPC
deadlines separately: each RPC can have a different deadline, or none at all.

Global default
--------------

Set the Helm value to provide a default for generated HTTP upstream clusters:

.. code-block:: yaml

   envoy:
     upstreamTCPUserTimeoutSeconds: 120

The value must be an integer from ``0`` to ``2147483`` seconds. ``0`` leaves the
socket option unset. The Operator also accepts
``--proxy-upstream-tcp-user-timeout-seconds`` or the equivalent environment
variable ``CILIUM_PROXY_UPSTREAM_TCP_USER_TIMEOUT_SECONDS``.

This setting applies to generated HTTP/1 and HTTP/2 upstream clusters, including
gRPC. It does not affect TLS passthrough or raw TCP clusters, L7 network-policy
proxies, or manually managed ``CiliumEnvoyConfig`` resources.

If the same backend Service and port are used by both HTTP and TLS passthrough
routes within one CEC, a nonzero timeout is rejected: those routes currently
share one Envoy cluster. Use separate backend Services or opt that Service out
with ``0s``. This prevents silently dropping the HTTP timeout or applying it to
passthrough connections.

Per-Service override
--------------------

Add ``service.cilium.io/upstream-tcp-user-timeout`` to the **backend Service**
referenced by a Route's ``backendRefs`` or an Ingress backend. The override
applies to all ports of that Service and takes precedence over the global
default. For GAMMA, this is the backend Service, which may be different from the
Service in ``parentRefs``.

.. code-block:: yaml

   apiVersion: v1
   kind: Service
   metadata:
     name: example-backend
     annotations:
       service.cilium.io/upstream-tcp-user-timeout: "60s"
   spec:
     selector:
       app: example-backend
     ports:
       - port: 8080
         targetPort: 8080

The annotation accepts Go duration strings, for example ``60s``, ``2m``, or
``1500ms``. The value must be non-negative, an exact number of milliseconds, and
at most ``2147483647ms``. Set it to ``0s`` to leave the socket option unset for
this Service even when the global default is enabled. Remove the annotation to
inherit the global default again.

Annotation changes trigger reconciliation of the consuming Gateways, GAMMA
parent Services, and Ingresses. Invalid annotations cause reconciliation to fail
with an error identifying the backend Service; the last valid CEC configuration
is retained. An invalid annotation prevents initial CEC creation when no prior
valid configuration exists. Correct or remove the annotation to resume updates.

Operational considerations
--------------------------

The Operator writes the resolved timeout to the Envoy Cluster resources in its
generated CEC. The socket option is applied when new upstream connections are
created. Updating a Service or CEC does not directly change the timeout of
already-open sockets; connection replacement follows Envoy's configuration and
pool lifecycle. Verify the new configuration and a newly established connection
when testing a changed value.

Choose a timeout that tolerates expected network disruption. Closing a shared
HTTP/2 connection can fail several in-flight requests at once; retries and
application deadlines remain separate concerns. The example ``120`` seconds is
an explicit deployment choice, not a built-in default.

.. warning::

   This feature adds a per-cluster ``upstream_bind_config``. Envoy gives that
   configuration precedence over the bootstrap ClusterManager's
   ``upstream_bind_config``; the two are not merged by Envoy. If you customize
   bootstrap bind addresses or socket options, review that interaction before
   enabling this feature. A zero timeout only disables injection by this
   feature; it does not cancel socket options configured independently.
