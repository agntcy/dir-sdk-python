# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

import os


class DockerConfig:
    """
    A class for using dirctl via the Docker image.
    """

    DEFAULT_DIRCTL_IMAGE = "ghcr.io/agntcy/dir-ctl"
    DEFAULT_DIRCTL_IMAGE_TAG = "latest"

    def __init__(
        self,
        dirctl_image: str = DEFAULT_DIRCTL_IMAGE,
        dirctl_image_tag: str = DEFAULT_DIRCTL_IMAGE_TAG,
        envs: dict[str, str] = None,
        mounts: list[str] = None,
        user: str | None = None,
    ) -> None:
        if envs is None:
            envs = {}
        if mounts is None:
            mounts = []

        self.dirctl_image = dirctl_image
        self.dirctl_image_tag = dirctl_image_tag
        self.envs: dict[str, str] = envs
        self.mounts: list[str] = mounts
        self.user = user

    def get_commands(self) -> list[str]:
        self.prune_mounts()
        commands = ["docker", "container", "run", "--name=dir-ctl", "--rm", "--network", "host"]
        if self.user:
            commands.extend(["--user", self.user])
        for key, val in self.envs.items():
            commands.append("--env")
            commands.append(f"{key}={val}")
        for mount in self.mounts:
            commands.append("--mount")
            commands.append(mount)
        commands.append(f"{self.dirctl_image}:{self.dirctl_image_tag}")
        return commands

    def prune_mounts(self) -> None:
        mounts = []
        for mount in self.mounts:
            if mount.startswith("type=bind"):
                type, src, dst = mount.split(",")
                _, src = src.split("=")
                if os.path.isfile(src):
                    mounts.append(mount)
        self.mounts = mounts


class Config:
    DEFAULT_SERVER_ADDRESS = "127.0.0.1:8888"
    DEFAULT_DIRCTL_PATH = "dirctl"
    DEFAULT_SPIFFE_SOCKET_PATH = ""
    DEFAULT_AUTH_MODE = ""
    DEFAULT_JWT_AUDIENCE = ""
    DEFAULT_TLS_CA_FILE = ""
    DEFAULT_TLS_CERT_FILE = ""
    DEFAULT_TLS_KEY_FILE = ""

    def __init__(
        self,
        server_address: str = DEFAULT_SERVER_ADDRESS,
        dirctl_path: str = DEFAULT_DIRCTL_PATH,
        spiffe_socket_path: str = DEFAULT_SPIFFE_SOCKET_PATH,
        auth_mode: str = DEFAULT_AUTH_MODE,
        jwt_audience: str = DEFAULT_JWT_AUDIENCE,
        tls_ca_file: str = DEFAULT_TLS_CA_FILE,
        tls_cert_file: str = DEFAULT_TLS_CERT_FILE,
        tls_key_file: str = DEFAULT_TLS_KEY_FILE,
        docker_config: DockerConfig = None,
    ) -> None:
        self.server_address = server_address
        self.dirctl_path = dirctl_path
        self.spiffe_socket_path = spiffe_socket_path
        self.auth_mode = auth_mode  # '' for insecure, 'x509', 'jwt' or 'tls'
        self.jwt_audience = jwt_audience
        self.tls_ca_file = tls_ca_file
        self.tls_cert_file = tls_cert_file
        self.tls_key_file = tls_key_file
        self.docker_config = docker_config
        if dirctl_path and docker_config:
            raise ValueError("You cannot specify both dirctl_path and docker_config.")

    def get_dirctl(self) -> list[str]:
        if self.dirctl_path:
            return [self.dirctl_path]
        else:
            return self.docker_config.get_commands()

    @staticmethod
    def load_from_env(env_prefix: str = "DIRECTORY_CLIENT_") -> "Config":
        """Load configuration from environment variables."""
        # Get dirctl path from environment variable without prefix
        dirctl_path = os.environ.get("DIRCTL_PATH")
        dirctl_image = os.environ.get("DIRCTL_IMAGE")
        dirctl_image_tag = os.environ.get("DIRCTL_IMAGE_TAG")

        docker_config = None
        if dirctl_image or dirctl_image_tag:
            docker_config = DockerConfig(
                dirctl_image or DockerConfig.DEFAULT_DIRCTL_IMAGE,
                dirctl_image_tag or DockerConfig.DEFAULT_DIRCTL_IMAGE_TAG,
                user="0:0",
            )

        # Use prefixed environment variables for other settings
        server_address = os.environ.get(
            f"{env_prefix}SERVER_ADDRESS",
            Config.DEFAULT_SERVER_ADDRESS,
        )
        spiffe_socket_path = os.environ.get(
            f"{env_prefix}SPIFFE_SOCKET_PATH",
            Config.DEFAULT_SPIFFE_SOCKET_PATH,
        )
        auth_mode = os.environ.get(
            f"{env_prefix}AUTH_MODE",
            Config.DEFAULT_AUTH_MODE,
        )
        jwt_audience = os.environ.get(
            f"{env_prefix}JWT_AUDIENCE",
            Config.DEFAULT_JWT_AUDIENCE,
        )
        tls_ca_file = os.environ.get(
            f"{env_prefix}TLS_CA_FILE",
            Config.DEFAULT_TLS_CA_FILE,
        )
        tls_cert_file = os.environ.get(
            f"{env_prefix}TLS_CERT_FILE",
            Config.DEFAULT_TLS_CERT_FILE,
        )
        tls_key_file = os.environ.get(
            f"{env_prefix}TLS_KEY_FILE",
            Config.DEFAULT_TLS_KEY_FILE,
        )

        return Config(
            server_address=server_address,
            dirctl_path=dirctl_path,
            spiffe_socket_path=spiffe_socket_path,
            auth_mode=auth_mode,
            jwt_audience=jwt_audience,
            tls_ca_file=tls_ca_file,
            tls_cert_file=tls_cert_file,
            tls_key_file=tls_key_file,
            docker_config=docker_config,
        )
