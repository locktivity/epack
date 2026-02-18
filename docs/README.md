# epack Documentation

Welcome to the epack documentation. This directory contains technical documentation for users, operators, and component authors.

## Getting Started

| Document | Description |
|----------|-------------|
| [Quickstart Guide](quickstart.md) | 5-minute hands-on tutorial |
| [Concepts](concepts.md) | How epack works (with diagrams) |

## User Guides

| Document | Description |
|----------|-------------|
| [Hardening Guide](hardening.md) | Secure deployment practices |

## Security

| Document | Description |
|----------|-------------|
| [Threat Model](threat-model.md) | Security objectives, assumptions, and non-goals |
| [Architecture](architecture.md) | Security-relevant internal structure |

## Component Protocol Specifications

These documents are for authors building collectors, tools, or remote adapters.

| Document | Description |
|----------|-------------|
| [Collector Protocol](collect-protocol.md) | Evidence gathering plugin specification |
| [Tool Protocol](tool-protocol.md) | Pack processing plugin specification |
| [Remote Protocol](remote-protocol.md) | Registry communication specification |
| [Component Requirements](component-rules.md) | RFC 2119 normative requirements |

## Release & Operations

| Document | Description |
|----------|-------------|
| [Releasing](releasing.md) | How to create a new epack release |

## External Documentation

- [CLI Reference](https://epack.dev/reference/cli): Full command documentation
- [Configuration Reference](https://epack.dev/reference/config): epack.yaml schema
- [Go API Reference](https://pkg.go.dev/github.com/locktivity/epack): Library documentation
- [Evidence Pack Specification](https://evidencepack.org/spec): The open standard
