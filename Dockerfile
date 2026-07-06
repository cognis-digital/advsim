FROM python:3.12-slim

LABEL org.opencontainers.image.title="advsim" \
      org.opencontainers.image.description="Benign, authorized-use-only adversary-emulation and detection-validation harness (MITRE ATT&CK)." \
      org.opencontainers.image.source="https://github.com/cognis-digital/advsim" \
      org.opencontainers.image.licenses="COCL-1.0"

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir . && pip cache purge || true

# Run as an unprivileged user; advsim only needs a temp dir for its sandbox.
RUN useradd --create-home advsim
USER advsim

ENTRYPOINT ["advsim"]
CMD ["list"]
