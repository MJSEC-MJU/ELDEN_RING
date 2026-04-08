"""Source code mapper - maps attack target endpoint to source code location.

Uses a route map loaded from a ConfigMap-mounted JSON file.
"""

import json
import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class SourceMapper:
    def __init__(self, route_map_path: str = "/config/routes.json"):
        self.route_map: dict = {}
        if os.path.exists(route_map_path):
            with open(route_map_path, "r") as f:
                self.route_map = json.load(f)
            logger.info(f"Loaded route map with {len(self.route_map)} entries")
        else:
            logger.warning(f"Route map not found at {route_map_path}")

    def map(self, method: str, path: str) -> Optional[dict]:
        """
        Map endpoint to source code location.
        Returns None if not found (Phase 2 will do a full scan).
        """
        key = f"{method.upper()} {path}"
        mapping = self.route_map.get(key)
        if mapping:
            return {
                "file": mapping["file"],
                "function": mapping["function"],
                "line_start": mapping["line_start"],
                "line_end": mapping["line_end"],
            }
        return None
