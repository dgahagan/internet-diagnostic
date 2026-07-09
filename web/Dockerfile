FROM python:3.12-slim

# Stdlib only — no pip install, so the build works with no internet access
# (which is rather the point of this project).

WORKDIR /app
COPY app.py playbooks.py probes.py ./

ENV NETWATCH_DIR=/data
EXPOSE 8091

CMD ["python", "app.py"]
