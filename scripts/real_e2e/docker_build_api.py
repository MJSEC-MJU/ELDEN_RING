from __future__ import annotations

import argparse
import http.client
import io
import json
import os
import socket
import tarfile
import urllib.parse
from pathlib import Path


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str) -> None:
        super().__init__("localhost")
        self.socket_path = socket_path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(self.socket_path)
        self.sock = sock


def build_context_tar(context: Path) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for path in context.rglob("*"):
            rel = path.relative_to(context)
            if any(part in {".git", "__pycache__", ".pytest_cache"} for part in rel.parts):
                continue
            if path.is_file():
                tar.add(path, arcname=str(rel))
    return buf.getvalue()


def docker_build(context: Path, tag: str, socket_path: str) -> None:
    body = build_context_tar(context)
    query = urllib.parse.urlencode({"t": tag, "rm": "1", "pull": "0"})
    conn = UnixHTTPConnection(socket_path)
    conn.request(
        "POST",
        f"/build?{query}",
        body=body,
        headers={
            "Content-Type": "application/x-tar",
            "Content-Length": str(len(body)),
        },
    )
    response = conn.getresponse()
    output = response.read().decode("utf-8", errors="replace")
    for line in output.splitlines():
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            print(line)
            continue
        if "stream" in payload:
            print(payload["stream"], end="")
        if "error" in payload:
            raise RuntimeError(payload["error"])
    if response.status >= 400:
        raise RuntimeError(f"Docker build failed with HTTP {response.status}: {output}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a Docker image through the local Docker socket.")
    parser.add_argument("--context", required=True)
    parser.add_argument("--tag", default=os.environ.get("ELDEN_CANDIDATE_IMAGE"))
    parser.add_argument("--socket", default="/var/run/docker.sock")
    args = parser.parse_args()

    context = Path(args.context).resolve()
    if not args.tag:
        raise SystemExit("--tag or ELDEN_CANDIDATE_IMAGE is required")
    if not (context / "Dockerfile").exists():
        raise SystemExit(f"Dockerfile not found in build context: {context}")

    docker_build(context, args.tag, args.socket)
    print(f"built image {args.tag} from {context}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
