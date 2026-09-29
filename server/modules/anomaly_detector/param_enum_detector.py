import logging
from typing import Dict, Any, List, Set, Optional
from collections import deque
from sqlalchemy.future import select
from server.models.core import RequestLog
from server.modules.persistence.database import AsyncSessionLocal

logger = logging.getLogger(__name__)

class ParamEnumDetector:
    """
    Detects if an IP is scanning sequential resource IDs (BOLA/Enumeration probing).
    Example: Accessing /user/101, /user/102, /user/103 in 2 seconds.
    """
    def __init__(self, window_size: int = 50, thresholds: Dict[str, int] = {"sequential": 5}):
        self.window_size = window_size
        self.thresholds = thresholds
        # source_ip -> {endpoint_id: dequeof_ids}
        self.history = {}

    async def analyze_request(self, ip: str, endpoint_id: str, path: str):
        """
        Extracts numbers from path and looks for sequential trends per endpoint.
        """
        import re
        nums = [int(n) for n in re.findall(r'\d+', path)]
        if not nums: return False
        
        last_num = nums[-1] # Target the identifier (usually last)
        
        # Keep track of history 
        self.history.setdefault(ip, {}).setdefault(endpoint_id, deque(maxlen=self.window_size)).append(last_num)
        
        # Check if the last N IDs are sequential
        ids = list(self.history[ip][endpoint_id])
        if len(ids) >= self.thresholds["sequential"]:
            count = 0
            for i in range(1, len(ids)):
                if abs(ids[i] - ids[i-1]) == 1:
                    count += 1
                else:
                    count = 0
                
                if count >= self.thresholds["sequential"] - 1:
                    logger.warning(f"Sequential ID enumeration detected from {ip} on {endpoint_id}")
                    return True
        return False
