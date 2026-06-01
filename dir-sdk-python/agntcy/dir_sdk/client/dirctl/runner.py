# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Low-level helpers for invoking the dirctl CLI safely."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Sequence

from agntcy.dir_sdk.client.config import Config, DockerConfig


def _copy_docker_config(docker_config: DockerConfig) -> DockerConfig:
    return DockerConfig(
        dirctl_image=docker_config.dirctl_image,
        dirctl_image_tag=docker_config.dirctl_image_tag,
        envs=dict(docker_config.envs),
        mounts=list(docker_config.mounts),
        user=docker_config.user,
    )


def build_dirctl_base_command(
    config: Config,
    env: dict[str, str] | None = None,
    extra_mounts: Sequence[str] | None = None,
) -> list[str]:
    extra_mounts = list(extra_mounts or [])
    if config.dirctl_path:
        return [config.dirctl_path]
    if config.docker_config is None:
        msg = "Either dirctl_path or docker_config must be configured"
        raise RuntimeError(msg)

    docker_config = _copy_docker_config(config.docker_config)
    docker_config.envs.update(env)
    docker_config.mounts.extend(extra_mounts)
    return docker_config.get_commands()


def run_dirctl(
    config: Config,
    args: Sequence[str],
    *,
    env: dict[str, str] | None = None,
    timeout: int = 60,
    extra_mounts: Sequence[str] | None = None,
) -> None:
    command = [*build_dirctl_base_command(config, env=env, extra_mounts=extra_mounts), *args]
    shell_env = os.environ.copy()
    if env:
        shell_env.update(env)

    try:
        subprocess.run(
            command,
            check=True,
            capture_output=True,
            env=shell_env,
            timeout=timeout,
        )
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.decode("utf-8", errors="ignore")
        msg = f"dirctl command failed with return code {e.returncode}: {stderr}"
        raise RuntimeError(msg) from e
    except subprocess.TimeoutExpired as e:
        msg = "dirctl command timed out"
        raise RuntimeError(msg) from e
