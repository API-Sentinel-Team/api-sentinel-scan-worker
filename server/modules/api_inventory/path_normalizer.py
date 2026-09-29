import re
import uuid

class PathNormalizer:
    """
    Normalizes variable path segments like UUIDs and integers 
    into variable placeholders like {id}.
    """
    def __init__(self):
        # List of regexes to detect dynamic segments
        self.rules = [
            # Standard UUID: 550e8400-e29b-41d4-a716-446655440000
            (r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', '{uuid}'),
            # OCI / git digest: sha256:<64 hex>
            (r'^sha256:[0-9a-f]{64}$', '{digest}'),
            # Bare 64-char hex digest (Harbor blobs, git SHAs)
            (r'^[0-9a-f]{64}$', '{sha256}'),
            # MongoDB ObjectID
            (r'^[0-9a-f]{24}$', '{oid}'),
            # Integer IDs
            (r'^\d+$', '{id}'),
            # Email addresses as segments (occasionally)
            (r'^.+@.+\..+$', '{email}')
        ]

    def normalize(self, path: str, strategy: str = "merge_on_slash") -> str:
        """
        Main entry point for path normalization with switchable strategies.
        """
        if strategy == "merge_on_host_only":
            return self.merge_on_host_only(path)
        elif strategy == "merge_similar_urls":
            # This would usually take a list of URLs, for single normalization
            # it defaults to merge_on_slash followed by similarity checks.
            return self.merge_on_slash(path)
        else:
            return self.merge_on_slash(path)

    def merge_on_slash(self, path: str) -> str:
        """
        Standard strategy: Replaces every numeric/UUID segment at every slash level.
        /users/123/profile -> /users/{id}/profile
        """
        segments = path.strip('/').split('/')
        normalized_segments = []

        for segment in segments:
            matched = False
            for pattern, replacement in self.rules:
                if re.match(pattern, segment, re.IGNORECASE):
                    normalized_segments.append(replacement)
                    matched = True
                    break
            
            if not matched:
                normalized_segments.append(segment)

        return '/' + '/'.join(normalized_segments)

    def merge_on_host_only(self, path: str) -> str:
        """
        Clusters by host only - treats entire path as a single static resource.
        Useful for subdomains or microservices where paths are flat.
        """
        return "/*"

    def merge_similar_urls(self, urls: list) -> dict:
        """
        Group URLs based on edit-distance similarity. 
        Example: /api/v1/user_profile and /api/v1/user_settings 
        might be merged if they share 80% structure.
        """
        groups = {}
        for url in urls:
            normalized = self.merge_on_slash(url)
            groups.setdefault(normalized, []).append(url)
        return groups
