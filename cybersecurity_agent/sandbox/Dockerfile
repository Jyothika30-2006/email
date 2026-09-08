# SENTINEL-IR static-analysis sandbox.
# Design: smallest possible image whose ONLY job is to read bytes and print JSON.
# No CMD/ENTRYPOINT — the runner passes the scanner argv explicitly, so this image
# can never be asked to "run something else" by the agent.
FROM python:3.12-slim-bookworm

# Optional extras; each is used only if present, and every one of them is a
# READ-ONLY static tool (none of them executes a document).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      libimage-exiftool-perl \
      libmagic1 \
      yara \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 1000 --create-home --shell /usr/sbin/nologin analyst

RUN pip install --no-cache-dir oletools olefile yara-python pypdf \
 && python3 -c "import oletools.olevba; print('olevba ok')"

COPY scanner_script.py /work-scanner/scanner_script.py
RUN chmod 0444 /work-scanner/scanner_script.py && chown -R 1000:1000 /work-scanner

# Run as uid 1000 (root capability is dropped by the runner anyway).
USER 1000:1000
WORKDIR /work

# No ENTRYPOINT/CMD by design. The host runner supplies:
#   python3 /work/scanner_script.py --file /work/evidence/<x> --out /out/report.json
