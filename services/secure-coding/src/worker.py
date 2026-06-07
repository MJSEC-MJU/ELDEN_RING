from __future__ import annotations

from .secure_coding_plane.worker import SecureCodingWorker


def main() -> int:
    worker = SecureCodingWorker()
    try:
        worker.run_forever()
    finally:
        worker.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
