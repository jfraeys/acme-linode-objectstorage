import os
from pathlib import Path


def get_env_secrets(
    name: str, path: Path = Path(Path.cwd() / "secrets/")
) -> str | None:
    """
    Get an environment variable from either a file in the project secrets directory or an environment variable.

    Args:
        name (str): Environment variable name.
        path (Path): Path to the secrets directory (default: "secrets/").

    Returns:
        str: The environment variable.

    Raises:
        EnvironmentError: If the environment variable or secret file is not found.
    """
    secret = os.environ.get(name)

    if not secret and (path / name).exists():
        secret = (path / name).read_text().rstrip("\n")
        return secret
    elif not secret and not (path / name).exists():
        raise EnvironmentError(
            f"Environment variable and/or secret file variable: {name} not found"
        )

    return secret