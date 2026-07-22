FROM python:3.14-slim

ENV HOME=/tmp \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /opt/previewshield

COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN python -m pip install . \
    && python -m pip check

# GitHub requires the image's default user for its workspace and file-command
# mounts. The action itself uses an exec-form entrypoint and invokes no shell.
WORKDIR /github/workspace

ENTRYPOINT ["python", "-m", "previewshield.action"]
