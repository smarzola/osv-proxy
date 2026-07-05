# Repository Instructions

- This repository is currently in documentation-only bootstrap state. Do not add implementation code until explicitly requested.
- Keep the product centered on deterministic package policy enforcement, not broad security scanning.
- Keep npm and PyPI specifics inside ecosystem adapter documentation and, later, adapter modules. The core policy model should stay ecosystem-neutral.
- Do not add an in-process memory metadata cache. Metadata caching is either disabled or cachebox-backed.
- Preserve the core invariant: policy is checked during metadata generation and checked again during artifact serving.
