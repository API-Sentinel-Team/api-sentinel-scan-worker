import numpy as np
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)

class DistributionCalculator:
    """
    Calculates statistical 'normalcy' for per-endpoint traffic rates.
    Identifies outliers based on standard deviation (3-sigma rule).
    """
    def __init__(self):
        # endpoint_id -> [count_per_minute_past_hour]
        self.stats = {}

    def update(self, endpoint_id: str, count: int):
        """
        Record the request count for a specific minute.
        """
        self.stats.setdefault(endpoint_id, deque(maxlen=60)).append(count)

    def is_anomalous(self, endpoint_id: str, current_count: int) -> bool:
        """
        Returns True if current_count exceeds 3 standard deviations from the mean.
        """
        history = list(self.stats.get(endpoint_id, []))
        if len(history) < 10: return False # Need more data for baseline
        
        mean = np.mean(history)
        std = np.std(history)
        
        # 3-sigma (three standard deviations) threshold
        threshold = mean + (3 * std)
        
        if current_count > threshold and current_count > 100: # Min floor to avoid small numbers
            logger.warning(f"Abnormal burst on {endpoint_id}: {current_count} req/min vs baseline {mean:.1f}")
            return True
        return False
from collections import deque
