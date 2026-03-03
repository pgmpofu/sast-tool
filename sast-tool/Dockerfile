FROM python:3.12-slim

LABEL maintainer="Your Name <you@example.com>"
LABEL description="SAST Tool — Language-agnostic Static Application Security Testing"
LABEL version="1.0.0"

# Security: run as non-root
RUN groupadd -r sast && useradd -r -g sast -d /app -s /sbin/nologin sast

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY sast/ ./sast/
COPY rules/ ./rules/
COPY main.py .

# Output directory for reports
RUN mkdir -p /reports && chown sast:sast /reports

USER sast

# /src is where users mount their codebase
VOLUME ["/src", "/reports"]

ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
