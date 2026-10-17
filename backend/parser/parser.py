import logging
from typing import Dict, Any, Optional
from pydantic import ValidationError
from backend.parser.models import NormalizedEvent
from backend.parser.normalizer import normalize_raw_event

logger = logging.getLogger(__name__)

class LogParser:
    def parse(self, raw_event: Dict[str, Any]) -> Optional[NormalizedEvent]:
        try:
            normalized_dict = normalize_raw_event(raw_event)
            return NormalizedEvent(**normalized_dict)
        except ValidationError as e:
            logger.error(f"Validation error parsing event: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error parsing event: {e}")
            return None
