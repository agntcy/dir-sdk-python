# Release

This document outlines the process of creating a new release
for the Directory Python SDK.

## 1. Create a release branch

Create a branch for the new release:

1. Update the SDK version in:
   - `pyproject.toml`
   - `examples/pyproject.toml`
   - `.github/ISSUE_TEMPLATE/bug_report.yml`
2. Update the dependencies if necessary:
   - [agntcy-dir-grpc-python](https://buf.build/agntcy/dir/sdks/v1.2.0%3Agrpc/python?version=v1.78.0) (Buf SDK)
   - [agntcy-dir-protocolbuffers-python](https://buf.build/agntcy/dir/sdks/v1.2.0%3Aprotocolbuffers/python?version=v34.0) (Buf SDK)
   - `.github/workflows/ci.yaml` (dir & dir-ctl version)
3. Add an entry to `CHANGELOG.md`

## 2. Create and push tags

After the release branch is merged, update your main branch:

```sh
git checkout main
git pull origin main
```

To trigger the release workflow, create and push the release tag
for the last commit:

```sh
git tag -a v1.2.1
git push origin v1.2.1
```
