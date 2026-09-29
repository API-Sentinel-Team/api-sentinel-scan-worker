import hashlib

class RequestDeduplicator:
    """
    Handles deduplication of requests by creating stable fingerprints.
    """
    def get_fingerprint(self, request) -> str:
        """
        Creates a fingerprint based on method, host, path, and sorted query/body keys.
        """
        # We focus on the structure (params) rather than values for broad deduplication
        data = {
            "method": request.method,
            "host": request.host,
            "path": request.path,
            "query_keys": sorted(request.query.keys()),
            "content_type": request.headers.get("Content-Type", "")
        }
        
        fingerprint_raw = "|".join([
            data["method"],
            data["host"],
            data["path"],
            ",".join(data["query_keys"]),
            data["content_type"]
        ])
        
        return hashlib.sha256(fingerprint_raw.encode("utf-8")).hexdigest()

    def is_duplicate(self, fingerprint: str) -> bool:
        # Implementation for memory-based or Redis-based tracking
        return False
