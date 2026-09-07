# Changelog

[agntcy/dir]: https://github.com/agntcy/dir
[agntcy/dir-sdk-python]: https://github.com/agntcy/dir-sdk-python

## 1.7.0 (2026-09-04)

### Changed

- Updated buf-generated SDK dependencies to track [agntcy/dir][agntcy/dir] `v1.7.0`.
- Bumped the directory chart and `dirctl` image used in CI to `v1.7.0`.

## 1.5.0 (2026-06-18)

### Added

- `AIFinderService` client methods: `list_agents`, `get_agent`, `export_agent`, and `get_well_known_catalog`.
- `catalog_v1` model re-exports for AI Catalog protobuf types.
- Integration tests for AI Finder against catalog-projectable OASF records.

### Changed

- Updated buf-generated SDK dependencies to track [agntcy/dir][agntcy/dir] `v1.5.0`.
- Bumped the directory chart and `dirctl` image used in CI to `v1.5.0`.

## 1.4.0 (2026-06-12)

### Added

- `search_routing` for network-wide `RoutingService.Search`.
- `delete_referrer` for `StoreService.DeleteReferrer`.
- Annotation-based search support (`RECORD_QUERY_TYPE_ANNOTATION`) in tests and examples.

### Changed

- Updated buf-generated SDK dependencies to track [agntcy/dir][agntcy/dir] `v1.4.0`.
- Bumped the directory chart and `dirctl` image used in CI to `v1.4.0`.

## 1.3.0 (2026-05-12)

### Changed

- Updated `agntcy-dir-grpc-python` and `agntcy-dir-protocolbuffers-python`
  buf-generated SDKs to track [agntcy/dir][agntcy/dir] `v1.3.0`.
- Bumped the directory chart and `dirctl` image used in CI to `v1.3.0`.

### Removed

- Removed unused `.cz.toml` Commitizen configuration.

## 1.2.1 (2026-04-15)

### Added

The Directory Python SDK has been migrated from the [agntcy/dir][agntcy/dir]
repository to the [agntcy/dir-sdk-python][agntcy/dir-sdk-python] repository.
