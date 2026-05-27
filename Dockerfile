FROM python:3.12-slim

LABEL org.opencontainers.image.title="dart_sast"
LABEL org.opencontainers.image.description="Static Application Security Testing for Dart/Flutter"
LABEL org.opencontainers.image.source="https://github.com/seu-usuario/dart-sast"
LABEL org.opencontainers.image.licenses="MIT"

# Non-root user for security
RUN useradd --create-home --shell /bin/bash scanner

WORKDIR /app

# Install dependencies first (layer cache friendly)
COPY pyproject.toml ./
RUN pip install --no-cache-dir pyyaml

# Copy source
COPY dart_sast/ ./dart_sast/
COPY rules/      ./rules/

# Switch to non-root
USER scanner

# /src is where the user mounts their project
VOLUME ["/src"]

ENTRYPOINT ["python", "-m", "dart_sast"]
CMD ["--help"]