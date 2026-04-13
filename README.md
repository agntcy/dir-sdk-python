# Directory Python SDK

[![Release](https://img.shields.io/github/v/release/agntcy/dir-sdk-python)](CHANGELOG.md)

## About The Project

The Directory Python SDK provides a simple way to interact with the Directory API.
It allows developers to integrate and use Directory functionality from their Python applications with ease.

## Getting Started

To get a local copy up and running follow these simple steps.

### Prerequisites

- Python 3.10 or higher
- Directory server instance
- [dirctl](https://github.com/agntcy/dir/releases) - Directory CLI binary

### Installation

```sh
uv add agntcy-dir --index https://buf.build/gen/python
```

## Usage

### Configuration

The SDK can be configured either via environment variables:

```sh
# Environment variables (insecure mode, default)
export DIRECTORY_CLIENT_SERVER_ADDRESS="localhost:8888"
export DIRCTL_PATH="/path/to/dirctl"

# Environment variables (X.509 authentication)
export DIRECTORY_CLIENT_SERVER_ADDRESS="localhost:8888"
export DIRECTORY_CLIENT_AUTH_MODE="x509"
export DIRECTORY_CLIENT_SPIFFE_SOCKET_PATH="/tmp/agent.sock"

# Environment variables (JWT authentication)
export DIRECTORY_CLIENT_SERVER_ADDRESS="localhost:8888"
export DIRECTORY_CLIENT_AUTH_MODE="jwt"
export DIRECTORY_CLIENT_SPIFFE_SOCKET_PATH="/tmp/agent.sock"
export DIRECTORY_CLIENT_JWT_AUDIENCE="spiffe://example.org/dir-server"
```

Or via a `Config` object:

```python
from agntcy.dir_sdk.client import Config, Client

# Insecure mode (default, for development only)
config = Config(
    server_address="localhost:8888",
    dirctl_path="/usr/local/bin/dirctl"
)
client = Client(config)

# X.509 authentication with SPIRE
x509_config = Config(
    server_address="localhost:8888",
    dirctl_path="/usr/local/bin/dirctl",
    spiffe_socket_path="/tmp/agent.sock",
    auth_mode="x509"
)
x509_client = Client(x509_config)

# JWT authentication with SPIRE
jwt_config = Config(
    server_address="localhost:8888",
    dirctl_path="/usr/local/bin/dirctl",
    spiffe_socket_path="/tmp/agent.sock",
    auth_mode="jwt",
    jwt_audience="spiffe://example.org/dir-server"
)
jwt_client = Client(jwt_config)
```

### Error Handling

The SDK primarily raises `grpc.RpcError` exceptions for gRPC communication issues and `RuntimeError` for configuration problems:

```python
import grpc
from agntcy.dir_sdk.client import Client

try:
    client = Client()
    records = client.list(list_request)
except grpc.RpcError as e:
    # Handle gRPC errors
    if e.code() == grpc.StatusCode.NOT_FOUND:
        print("Resource not found")
    elif e.code() == grpc.StatusCode.UNAVAILABLE:
        print("Server unavailable")
    else:
        print(f"gRPC error: {e.details()}")
except RuntimeError as e:
    # Handle configuration or subprocess errors
    print(f"Runtime error: {e}")
```

Common gRPC status codes:
- `NOT_FOUND`: Resource doesn't exist
- `ALREADY_EXISTS`: Resource already exists
- `UNAVAILABLE`: Server is down or unreachable
- `PERMISSION_DENIED`: Authentication/authorization failure
- `INVALID_ARGUMENT`: Invalid request parameters

_For more examples, please refer to the [Documentation](https://docs.agntcy.org/dir/directory-sdk/#python-sdk) or
the [Wiki](https://github.com/agntcy/dir-sdk-python/wiki)_

## Roadmap

See the [open issues](https://github.com/agntcy/dir-sdk-python/issues) for a list
of proposed features (and known issues).

## Contributing

Contributions are what make the open source community such an amazing place to
learn, inspire, and create. Any contributions you make are **greatly
appreciated**. For detailed contributing guidelines, please see
[CONTRIBUTING.md](CONTRIBUTING.md)

## License

Distributed under the Apache 2.0 License. See [LICENSE](LICENSE) for more
information.

## Contact

Project Link:
[https://github.com/agntcy/dir-sdk-python](https://github.com/agntcy/dir-sdk-python)
