## 6 Runtime modes

The current mode is set once at startup via the **`COYOTE_RUNTIME_MODE`** environment
variable (or `runtime.mode` in the root YAML).  
MCP injects the value into every container as `MODE=<value>` and launches only the
units whose `unit.spec.json` declares that mode in the `"modes"` list.

| Mode | Behaviour | Typical use-case |
|------|-----------|------------------|
| **production** | Real adapters only—no extra logging. | Trade against live venues. |
| **recording**  | Operates like production **and** streams every payload to `rec_stream:*`. | Capture live traffic for later analysis. |
| **replay**     | The **replay-player** unit re-publishes captured events at their original (or scaled) timestamps. | Deterministic back-testing, bug repro. |
| **simulation** | Replaces venues with synthetic engines; **simulation-controller** can inject latency and deterministic fills. | Strategy R&D without market risk. |
| **debug**      | Mirrors each message to `debug.<channel>` and logs full payloads. | In-depth troubleshooting on a staging box. |
| **testing**    | All adapters replaced by finite mocks. | CI unit/integration tests. |

### Mode-specific core units

| Unit | Folder | Active modes | Role |
|------|--------|--------------|------|
| **Recorder** | `units/core/recorder` | `recording` | Writes raw events to Redis Stream. |
| **Replay Player** | `units/core/replay-player` | `replay` | Re-injects recorded events into the bus. |
| **Simulation Controller** | `units/core/simulation-controller` | `simulation` | Tweaks fills, latency, and synthetic prices. |
| **Debug Proxy** | `units/core/debug-proxy` | `debug` | Mirrors traffic to `debug.*` channels. |
| **Metrics** | `units/core/metrics` | *all* | Publishes Prometheus metrics and heartbeats. |

---

## 7 Mode-aware interfaces

Every infra module contains a factory that selects a concrete implementation
based on `MODE`:

```
infra/http/
  interfaces/                 http_client.h           (pure interface)
  factory/                    http_client_factory.*
  modes/
    real/       http_client_real.*
    record/     http_client_record.*
    replay/     http_client_replay.*
    simulation/ http_client_simulation.*
    debug/      http_client_debug.*
    mock/       http_client_mock.*        # for testing
```

Example (C++):

```cpp
#include <coyote/http/http_client_factory.h>
auto client = coyote::http::MakeHttpClient(Runtime::Mode());
```

The same naming scheme (`HttpClientReal`, `HttpClientRecord`, …) applies to
.NET, TypeScript, and Python bindings.
