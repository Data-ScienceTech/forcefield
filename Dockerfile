FROM python:3.12-slim

LABEL org.opencontainers.image.title="ForceField AI Security Scanner"
LABEL org.opencontainers.image.description="Zero-dependency AI security library -- prompt-injection detection, PII redaction, content safety, rate limiting, abuse detection, tool governance for LLMs."
LABEL org.opencontainers.image.url="https://datasciencetech.ca/en/python-sdk"
LABEL org.opencontainers.image.source="https://github.com/Data-ScienceTech/forcefield"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.vendor="Data Science Technologies"

RUN pip install --no-cache-dir forcefield==0.7.2

ENTRYPOINT ["forcefield"]
CMD ["--help"]
