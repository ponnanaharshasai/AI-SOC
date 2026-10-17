import json
import logging
import os
from typing import List, Dict, Any
from backend.collectors.base import BaseCollector

logger = logging.getLogger(__name__)

class SampleLogCollector(BaseCollector):
    def __init__(self, file_path: str):
        self.file_path = file_path

    def collect(self) -> List[Dict[str, Any]]:
        events = []
        if not os.path.exists(self.file_path):
            logger.error(f"Log file not found: {self.file_path}")
            return events

        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                        events.append(event)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Malformed JSON at {self.file_path}:{line_num} - {str(e)}")
        except PermissionError:
            logger.error(f"Permission denied reading: {self.file_path}")
        except Exception as e:
            logger.error(f"Unexpected error reading {self.file_path}: {str(e)}")

        return events
