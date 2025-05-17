# CoyoteSense Platform

Hybrid event-driven, actor-based automation platform with AI at its core. Designed for trading, finance, payments, and analytics.

## Main features:

- YAML-based (`CoyoteFlow`) configurations.
- Compiled to Docker Compose/Kubernetes (`CoyoteCompiler`).
- Redis-based low-latency event-driven core.
- Actor-based concurrency with Docker Compose/Kubernetes supervision.

## Docs Structure:

- [High-Level Design](docs/high_level_design.md)
- [Modules & Units Classification](docs/modules_units_classification.md)
- [Glossary & Syntax](docs/glossary_and_syntax_primitives.md)
- [Proto File Structure](docs/model_proto_structure.md)
- [Runtime Modes](docs/coyoteflow_modes.md)

## Usage

Compile a `coyoteflow.yml` into infrastructure configurations:

```shell
./CoyoteCompiler build coyoteflow.yml --target=k8s
./CoyoteCompiler build coyoteflow.yml --target=compose
```
