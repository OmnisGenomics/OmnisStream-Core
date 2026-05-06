---
page_id: diagrams
page_type: diagrams
generation_mode: inferred
freshness_status: new
updated_at: 2026-05-06T23:02:17.028Z
---

<details>
<summary>Build metadata</summary>

```json
{
  "freshnessKey": "1a58dacf8f69015096b484b7ab47d92a8522f1ce",
  "plannerReason": "Generated to provide a compact architecture and dependency overview.",
  "changedPaths": [],
  "dependencyPaths": [],
  "dependencyEvidenceIds": [],
  "evidenceIds": [],
  "qualityWarnings": []
}

```
</details>

# Diagrams

Generated 4 diagrams.

## Diagram Navigation

- [Component Overview](#component-overview) (component-overview; 9 nodes; 8 edges; omitted 157 nodes / 157 edges)
- [Dependency Graph](#dependency-graph) (dependency-graph; 15 nodes; 16 edges; omitted 0 nodes / 1191 edges)
- [Directory Map](#directory-map) (directory-map; 7 nodes; 6 edges)
- [Subsystem Clusters](#subsystem-clusters) (component-overview; 6 nodes; 2 edges; omitted 0 nodes / 715 edges)

## Related Pages

- [architecture](architecture.md)
- [dependencies](dependencies.md)
- [runtime](runtime.md)

## Component Overview

Shows the most prominent inferred components connected to the repository root.

Explained in:
- [Architecture Summary](architecture.md#architecture-summary)
- [Graph Hotspots](architecture.md#architecture-hotspots)
- [Design-Shaping Dependencies](dependencies.md#design-shaping-dependencies)

Interpretation note:
- Interpretation: use this view to see the main repository-owned components and their highest-level relationships before drilling into page-level details. Favor it when you need a fast inventory of the system surface.

Rendered surface:
- rendered nodes: 9, rendered edges: 8

Node mix:
- component: 8, repository: 1

Omitted surface:
- omitted nodes: 157
- omitted edges: 157

```mermaid
graph LR
  repository["OmnisStream-Core"] --> component_bin_omnisstream["omnisstream"]
  repository["OmnisStream-Core"] --> component_bin_omnisstream_bench["omnisstream_bench"]
  repository["OmnisStream-Core"] --> component_bin_omnisstream_benchdiff["omnisstream_benchdiff"]
  repository["OmnisStream-Core"] --> component_bin_omnisstream_ffi_header["omnisstream_ffi_header"]
  repository["OmnisStream-Core"] --> component_cargo_crates_omnisstream["omnisstream"]
  repository["OmnisStream-Core"] --> component_cargo_crates_omnisstream_backend_api["omnisstream_backend_api"]
  repository["OmnisStream-Core"] --> component_cargo_crates_omnisstream_bench["omnisstream_bench"]
  repository["OmnisStream-Core"] --> component_cargo_crates_omnisstream_benchdiff["omnisstream_benchdiff"]

```

```dot
digraph RepoIntel {
  label="Component Overview";
  labelloc=t;
  rankdir=LR;
  node [shape=box];
  "repository" [label="OmnisStream-Core", shape=box];
  "component:bin:omnisstream" [label="omnisstream", shape=box];
  "component:bin:omnisstream_bench" [label="omnisstream_bench", shape=box];
  "component:bin:omnisstream_benchdiff" [label="omnisstream_benchdiff", shape=box];
  "component:bin:omnisstream_ffi_header" [label="omnisstream_ffi_header", shape=box];
  "component:cargo:crates/omnisstream" [label="omnisstream", shape=box];
  "component:cargo:crates/omnisstream_backend_api" [label="omnisstream_backend_api", shape=box];
  "component:cargo:crates/omnisstream_bench" [label="omnisstream_bench", shape=box];
  "component:cargo:crates/omnisstream_benchdiff" [label="omnisstream_benchdiff", shape=box];
  "repository" -> "component:bin:omnisstream" [label="contains"];
  "repository" -> "component:bin:omnisstream_bench" [label="contains"];
  "repository" -> "component:bin:omnisstream_benchdiff" [label="contains"];
  "repository" -> "component:bin:omnisstream_ffi_header" [label="contains"];
  "repository" -> "component:cargo:crates/omnisstream" [label="contains"];
  "repository" -> "component:cargo:crates/omnisstream_backend_api" [label="contains"];
  "repository" -> "component:cargo:crates/omnisstream_bench" [label="contains"];
  "repository" -> "component:cargo:crates/omnisstream_benchdiff" [label="contains"];
}

```

Structured graph:
- nodes: 9
- edges: 8

Layout:
- direction: LR
- strategy: root-spoke

Simplification:
- simplified: yes
- rendered nodes: 9
- rendered edges: 8
- omitted nodes: 157
- omitted edges: 157
- Omitted 157 lower-priority components to keep the overview readable.
- Switched to a left-to-right root-spoke layout to keep the largest components scannable.

Why these edges:
- Repository contains OmnisStream-Core as a prominent component.
- Repository contains OmnisStream-Core as a prominent component.
- Repository contains OmnisStream-Core as a prominent component.
- Repository contains OmnisStream-Core as a prominent component.
- Repository contains OmnisStream-Core as a prominent component.
- Repository contains OmnisStream-Core as a prominent component.

<details>
<summary>Citations:</summary>

- `docs/ffi_cmake.md`
- `docs/monarchic-launch.md`
- `README.md`
- `spec/omnisstream-spec/proto/README.md`
- `spec/omnisstream-spec/README.md`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/tools/validator/README.md`
- `crates/omnisstream_cli/src/main.rs`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_bench/src/main.rs`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_benchdiff/src/main.rs`
</details>

## Dependency Graph

Shows a sampled set of dependency and call relationships across indexed entities.

Explained in:
- [Graph Hotspots](architecture.md#architecture-hotspots)
- [Design-Shaping Dependencies](dependencies.md#design-shaping-dependencies)
- [Navigation Guidance](dependencies.md#dependency-guidance)

Interpretation note:
- Interpretation: use this graph to spot concentrated dependency hubs and outward package pressure across the repository. Favor it when you need to reason about coupling, likely blast radius, or external dependency concentration.

Rendered surface:
- rendered nodes: 15, rendered edges: 16

Node mix:
- symbol: 15

Omitted surface:
- omitted nodes: 0
- omitted edges: 1191

```mermaid
graph LR
  symbol_crates_omnisstream_bench_src_main_rs_blake3_256_hex_1213 --> symbol_crates_omnisstream_bench_src_main_rs_new_562
  symbol_crates_omnisstream_bench_src_main_rs_blake3_256_hex_1213 --> symbol_crates_omnisstream_src_hashing_rs_read_209
  symbol_crates_omnisstream_bench_src_main_rs_blake3_256_hex_1213 --> symbol_crates_omnisstream_src_hashing_rs_to_hex_37
  symbol_crates_omnisstream_bench_src_main_rs_generated_unix_ms_510 --> symbol_crates_omnisstream_bench_src_main_rs_now_406
  symbol_crates_omnisstream_bench_src_main_rs_git_head_524 --> symbol_crates_omnisstream_bench_src_main_rs_new_562
  symbol_crates_omnisstream_bench_src_main_rs_git_head_524 --> symbol_crates_omnisstream_bench_src_main_rs_read_optional_trimmed_517
  symbol_crates_omnisstream_bench_src_main_rs_main_597 --> symbol_crates_omnisstream_bench_src_main_rs_blake3_256_hex_1213
  symbol_crates_omnisstream_bench_src_main_rs_main_597 --> symbol_crates_omnisstream_bench_src_main_rs_from_args_115
  symbol_crates_omnisstream_bench_src_main_rs_main_597 --> symbol_crates_omnisstream_bench_src_main_rs_generated_unix_ms_510
  symbol_crates_omnisstream_bench_src_main_rs_main_597 --> symbol_crates_omnisstream_bench_src_main_rs_git_head_524
  symbol_crates_omnisstream_bench_src_main_rs_main_597 --> symbol_crates_omnisstream_bench_src_main_rs_read_optional_trimmed_517
  symbol_crates_omnisstream_bench_src_main_rs_main_597 --> symbol_crates_omnisstream_bench_src_main_rs_run_bench_795
  symbol_crates_omnisstream_bench_src_main_rs_main_597 --> symbol_crates_omnisstream_bench_src_main_rs_write_1134
  symbol_crates_omnisstream_bench_src_main_rs_main_597 --> symbol_crates_omnisstream_src_api_rs_set_compression_config_69
  symbol_crates_omnisstream_bench_src_main_rs_main_597 --> symbol_crates_omnisstream_src_api_rs_set_group_commit_config_36
  symbol_crates_omnisstream_bench_src_main_rs_main_597 --> symbol_crates_omnisstream_src_api_rs_set_relaxed_durability_21

```

```dot
digraph RepoIntel {
  label="Dependency Graph";
  labelloc=t;
  rankdir=LR;
  node [shape=box];
  "symbol:crates/omnisstream_bench/src/main.rs:blake3_256_hex:1213" [label="blake3_256_hex", shape=box];
  "symbol:crates/omnisstream_bench/src/main.rs:new:562" [label="new", shape=box];
  "symbol:crates/omnisstream/src/hashing.rs:read:209" [label="read", shape=box];
  "symbol:crates/omnisstream/src/hashing.rs:to_hex:37" [label="to_hex", shape=box];
  "symbol:crates/omnisstream_bench/src/main.rs:generated_unix_ms:510" [label="generated_unix_ms", shape=box];
  "symbol:crates/omnisstream_bench/src/main.rs:now:406" [label="now", shape=box];
  "symbol:crates/omnisstream_bench/src/main.rs:git_head:524" [label="git_head", shape=box];
  "symbol:crates/omnisstream_bench/src/main.rs:read_optional_trimmed:517" [label="read_optional_trimmed", shape=box];
  "symbol:crates/omnisstream_bench/src/main.rs:main:597" [label="main", shape=box];
  "symbol:crates/omnisstream_bench/src/main.rs:from_args:115" [label="from_args", shape=box];
  "symbol:crates/omnisstream_bench/src/main.rs:run_bench:795" [label="run_bench", shape=box];
  "symbol:crates/omnisstream_bench/src/main.rs:write:1134" [label="write", shape=box];
  "symbol:crates/omnisstream/src/api.rs:set_compression_config:69" [label="set_compression_config", shape=box];
  "symbol:crates/omnisstream/src/api.rs:set_group_commit_config:36" [label="set_group_commit_config", shape=box];
  "symbol:crates/omnisstream/src/api.rs:set_relaxed_durability:21" [label="set_relaxed_durability", shape=box];
  "symbol:crates/omnisstream_bench/src/main.rs:blake3_256_hex:1213" -> "symbol:crates/omnisstream_bench/src/main.rs:new:562" [label="calls"];
  "symbol:crates/omnisstream_bench/src/main.rs:blake3_256_hex:1213" -> "symbol:crates/omnisstream/src/hashing.rs:read:209" [label="calls"];
  "symbol:crates/omnisstream_bench/src/main.rs:blake3_256_hex:1213" -> "symbol:crates/omnisstream/src/hashing.rs:to_hex:37" [label="calls"];
  "symbol:crates/omnisstream_bench/src/main.rs:generated_unix_ms:510" -> "symbol:crates/omnisstream_bench/src/main.rs:now:406" [label="calls"];
  "symbol:crates/omnisstream_bench/src/main.rs:git_head:524" -> "symbol:crates/omnisstream_bench/src/main.rs:new:562" [label="calls"];
  "symbol:crates/omnisstream_bench/src/main.rs:git_head:524" -> "symbol:crates/omnisstream_bench/src/main.rs:read_optional_trimmed:517" [label="calls"];
  "symbol:crates/omnisstream_bench/src/main.rs:main:597" -> "symbol:crates/omnisstream_bench/src/main.rs:blake3_256_hex:1213" [label="calls"];
  "symbol:crates/omnisstream_bench/src/main.rs:main:597" -> "symbol:crates/omnisstream_bench/src/main.rs:from_args:115" [label="calls"];
  "symbol:crates/omnisstream_bench/src/main.rs:main:597" -> "symbol:crates/omnisstream_bench/src/main.rs:generated_unix_ms:510" [label="calls"];
  "symbol:crates/omnisstream_bench/src/main.rs:main:597" -> "symbol:crates/omnisstream_bench/src/main.rs:git_head:524" [label="calls"];
  "symbol:crates/omnisstream_bench/src/main.rs:main:597" -> "symbol:crates/omnisstream_bench/src/main.rs:read_optional_trimmed:517" [label="calls"];
  "symbol:crates/omnisstream_bench/src/main.rs:main:597" -> "symbol:crates/omnisstream_bench/src/main.rs:run_bench:795" [label="calls"];
  "symbol:crates/omnisstream_bench/src/main.rs:main:597" -> "symbol:crates/omnisstream_bench/src/main.rs:write:1134" [label="calls"];
  "symbol:crates/omnisstream_bench/src/main.rs:main:597" -> "symbol:crates/omnisstream/src/api.rs:set_compression_config:69" [label="calls"];
  "symbol:crates/omnisstream_bench/src/main.rs:main:597" -> "symbol:crates/omnisstream/src/api.rs:set_group_commit_config:36" [label="calls"];
  "symbol:crates/omnisstream_bench/src/main.rs:main:597" -> "symbol:crates/omnisstream/src/api.rs:set_relaxed_durability:21" [label="calls"];
}

```

Structured graph:
- nodes: 15
- edges: 16

Layout:
- direction: LR
- strategy: edge-ranked

Simplification:
- simplified: yes
- rendered nodes: 15
- rendered edges: 16
- omitted nodes: 0
- omitted edges: 1191
- Omitted 1191 lower-priority dependency edges to avoid an unreadable graph.
- Kept a rank-ordered sample of stronger edges and switched to a left-to-right layout for denser graphs.

Why these edges:
- symbol:crates/omnisstream_bench/src/main.rs:blake3_256_hex:1213 calls symbol:crates/omnisstream_bench/src/main.rs:new:562 via crates/omnisstream_bench/src/main.rs.
- symbol:crates/omnisstream_bench/src/main.rs:blake3_256_hex:1213 calls symbol:crates/omnisstream/src/hashing.rs:read:209 via crates/omnisstream_bench/src/main.rs.
- symbol:crates/omnisstream_bench/src/main.rs:blake3_256_hex:1213 calls symbol:crates/omnisstream/src/hashing.rs:to_hex:37 via crates/omnisstream_bench/src/main.rs.
- symbol:crates/omnisstream_bench/src/main.rs:generated_unix_ms:510 calls symbol:crates/omnisstream_bench/src/main.rs:now:406 via crates/omnisstream_bench/src/main.rs.
- symbol:crates/omnisstream_bench/src/main.rs:git_head:524 calls symbol:crates/omnisstream_bench/src/main.rs:new:562 via crates/omnisstream_bench/src/main.rs.
- symbol:crates/omnisstream_bench/src/main.rs:git_head:524 calls symbol:crates/omnisstream_bench/src/main.rs:read_optional_trimmed:517 via crates/omnisstream_bench/src/main.rs.
- symbol:crates/omnisstream_bench/src/main.rs:main:597 calls symbol:crates/omnisstream_bench/src/main.rs:blake3_256_hex:1213 via crates/omnisstream_bench/src/main.rs.
- symbol:crates/omnisstream_bench/src/main.rs:main:597 calls symbol:crates/omnisstream_bench/src/main.rs:from_args:115 via crates/omnisstream_bench/src/main.rs.
- symbol:crates/omnisstream_bench/src/main.rs:main:597 calls symbol:crates/omnisstream_bench/src/main.rs:generated_unix_ms:510 via crates/omnisstream_bench/src/main.rs.
- symbol:crates/omnisstream_bench/src/main.rs:main:597 calls symbol:crates/omnisstream_bench/src/main.rs:git_head:524 via crates/omnisstream_bench/src/main.rs.

<details>
<summary>Citations:</summary>

- `docs/ffi_cmake.md`
- `docs/monarchic-launch.md`
- `README.md`
- `spec/omnisstream-spec/proto/README.md`
- `spec/omnisstream-spec/README.md`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/tools/validator/README.md`
- `crates/omnisstream_cli/src/main.rs`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_bench/src/main.rs`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_benchdiff/src/main.rs`
</details>

## Directory Map

Shows top-level directory layout to orient unfamiliar agents.

Interpretation note:
- Interpretation: use this map to orient yourself in the repository layout before reading code. Favor it when you need to connect top-level paths to the graph surfaces shown elsewhere.

Rendered surface:
- rendered nodes: 7, rendered edges: 6

Node mix:
- directory: 6, repository: 1

```mermaid
graph TD
  repository["OmnisStream-Core"] --> _github[".github/"]
  repository["OmnisStream-Core"] --> crates["crates/"]
  repository["OmnisStream-Core"] --> docs["docs/"]
  repository["OmnisStream-Core"] --> examples["examples/"]
  repository["OmnisStream-Core"] --> include["include/"]
  repository["OmnisStream-Core"] --> spec["spec/"]

```

```dot
digraph RepoIntel {
  label="Directory Map";
  labelloc=t;
  rankdir=TB;
  node [shape=box];
  "repository" [label="OmnisStream-Core", shape=box];
  ".github" [label=".github/", shape=box];
  "crates" [label="crates/", shape=box];
  "docs" [label="docs/", shape=box];
  "examples" [label="examples/", shape=box];
  "include" [label="include/", shape=box];
  "spec" [label="spec/", shape=box];
  "repository" -> ".github" [label="contains"];
  "repository" -> "crates" [label="contains"];
  "repository" -> "docs" [label="contains"];
  "repository" -> "examples" [label="contains"];
  "repository" -> "include" [label="contains"];
  "repository" -> "spec" [label="contains"];
}

```

Structured graph:
- nodes: 7
- edges: 6

Layout:
- direction: TD
- strategy: linear-map

Simplification:
- simplified: no
- rendered nodes: 7
- rendered edges: 6
- omitted nodes: 0
- omitted edges: 0

Why these edges:
- .github/ is a top-level directory under the repository root.
- crates/ is a top-level directory under the repository root.
- docs/ is a top-level directory under the repository root.
- examples/ is a top-level directory under the repository root.
- include/ is a top-level directory under the repository root.
- spec/ is a top-level directory under the repository root.

<details>
<summary>Citations:</summary>

- `docs/ffi_cmake.md`
- `docs/monarchic-launch.md`
- `README.md`
- `spec/omnisstream-spec/proto/README.md`
- `spec/omnisstream-spec/README.md`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/tools/validator/README.md`
- `crates/omnisstream_cli/src/main.rs`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_bench/src/main.rs`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_benchdiff/src/main.rs`
</details>

## Subsystem Clusters

Shows a simplified subsystem graph grouped by dominant repository paths and graph-connected merges.

Explained in:
- [Subsystem Clusters](architecture.md#architecture-subsystems)
- [Architecture Summary](architecture.md#architecture-summary)

Interpretation note:
- Interpretation: use this clustering view to understand which source areas act like larger architectural slices and how strongly they connect. Favor it when you need a quick map of architectural boundaries instead of individual files or packages.

Rendered surface:
- rendered nodes: 6, rendered edges: 2

Node mix:
- subsystem: 6

Omitted surface:
- omitted nodes: 0
- omitted edges: 715

```mermaid
graph LR
  subgraph group_Cargo_toml["Cargo.toml/"]
    subsystem_root["root"]
  end
  subgraph group_crates["crates/"]
    subsystem_crates["crates"]
    subsystem_external["external"]
    subsystem_tests["tests"]
  end
  subgraph group_docs["docs/"]
    subsystem_docs["docs"]
  end
  subgraph group_spec["spec/"]
    subsystem_spec["spec"]
  end
  subsystem_crates ~~~ subsystem_spec
  subsystem_spec ~~~ subsystem_docs
  subsystem_spec --> subsystem_crates
  subsystem_crates --> subsystem_external

```

```dot
digraph RepoIntel {
  label="Subsystem Clusters";
  labelloc=t;
  rankdir=LR;
  node [shape=box];
  "subsystem:external" [label="external", shape=box];
  "subsystem:crates" [label="crates", shape=box];
  "subsystem:spec" [label="spec", shape=box];
  "subsystem:docs" [label="docs", shape=box];
  "subsystem:root" [label="root", shape=box];
  "subsystem:tests" [label="tests", shape=box];
  "subsystem:spec" -> "subsystem:crates" [label="depends_on", weight=7, penwidth=4.5];
  "subsystem:crates" -> "subsystem:external" [label="depends_on", weight=50, penwidth=6];
}

```

Structured graph:
- nodes: 6
- edges: 2

Layout:
- direction: LR
- strategy: hierarchy-banded

Simplification:
- simplified: yes
- rendered nodes: 6
- rendered edges: 2
- omitted nodes: 0
- omitted edges: 715
- Collapsed 715 additional subsystem edges from the rendered view.
- Grouped subsystem nodes by dominant path segment across 4 hierarchy buckets before rendering edges.
- Added band-order guide links so large hierarchy groups stay visually ordered before cross-subsystem edges are rendered.
- Used a left-to-right hierarchy-banded layout so dominant path groups stay ordered and visually clustered.
- Subsystem graph edges are condensed by repeated source/target pairs before sampling.

Why these edges:
- spec calls crates via spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py. 6 additional inferred edges reinforce this path. (7 inferred edges combined.)
- crates depends_on external via crates/omnisstream_bench/Cargo.toml. 49 additional inferred edges reinforce this path. (50 inferred edges combined.)

<details>
<summary>Citations:</summary>

- `docs/ffi_cmake.md`
- `docs/monarchic-launch.md`
- `README.md`
- `spec/omnisstream-spec/proto/README.md`
- `spec/omnisstream-spec/README.md`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/tools/validator/README.md`
- `crates/omnisstream_cli/src/main.rs`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_bench/src/main.rs`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_benchdiff/src/main.rs`
</details>

## Citations

<details>
<summary>Citations:</summary>

- `docs/ffi_cmake.md`
- `docs/monarchic-launch.md`
- `README.md`
- `spec/omnisstream-spec/proto/README.md`
- `spec/omnisstream-spec/README.md`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/tools/validator/README.md`
- `crates/omnisstream_cli/src/main.rs`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_bench/src/main.rs`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_benchdiff/src/main.rs`
</details>
