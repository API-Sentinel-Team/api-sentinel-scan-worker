import logging
from typing import Dict, Any, List, Set, Optional
from sqlalchemy.future import select
from server.models.core import APIEndpoint, SampleData
from server.modules.persistence.database import AsyncSessionLocal

logger = logging.getLogger(__name__)

class RelationshipMapper:
    """
    Identifies shared parameters and data flow dependencies across APIs.
    """
    async def find_relationships(self, account_id: int) -> Dict[str, List[str]]:
        """
        Groups endpoints by parameter names they use in request/response.
        Returns a map of {param_name: [endpoint_id1, endpoint_id2]}.
        """
        param_map = {}
        async with AsyncSessionLocal() as session:
            # 1. Fetch all captured samples
            stmt = select(SampleData)
            result = await session.execute(stmt)
            samples = result.scalars().all()

            for sample in samples:
                # 2. Extract keys from request/response
                # (Simple approach: look at keys in the JSON body)
                req_keys = self._extract_keys(sample.request.get('body', {}))
                res_keys = self._extract_keys(sample.response.get('body', {}))
                
                # 3. Associate keys with this endpoint
                all_keys = set(req_keys) | set(res_keys)
                for key in all_keys:
                    param_map.setdefault(key, set()).add(sample.endpoint_id)

        # Convert sets to lists for JSON serializability
        return {k: list(v) for k, v in param_map.items() if len(v) > 1}

    def _extract_keys(self, data: Any, prefix: str = "") -> List[str]:
        keys = []
        if isinstance(data, dict):
            for k, v in data.items():
                full_key = f"{prefix}.{k}" if prefix else k
                keys.append(full_key)
                keys.extend(self._extract_keys(v, full_key))
        elif isinstance(data, list) and data:
            keys.extend(self._extract_keys(data[0], f"{prefix}[]"))
        return keys
