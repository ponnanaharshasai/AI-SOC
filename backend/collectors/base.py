from abc import ABC, abstractmethod
from typing import List, Dict, Any

class BaseCollector(ABC):
    @abstractmethod
    def collect(self) -> List[Dict[str, Any]]:
        '''Collect and return raw events.'''
        pass
