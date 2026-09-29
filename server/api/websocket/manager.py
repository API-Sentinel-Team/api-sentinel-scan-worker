import json
import logging
from typing import List, Dict, Any, Optional
from fastapi import WebSocket, WebSocketDisconnect
import asyncio

logger = logging.getLogger(__name__)

class ConnectionManager:
    """
    Manages active WebSocket connections to the Dashboard.
    Enables real-time push for new vulnerabilities and scan progress.
    Adds authentication and parallel broadcasting for performance.
    """
    def __init__(self):
        # Store connections with metadata including user_id and account_id
        self.active_connections: Dict[WebSocket, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, token: Optional[str] = None) -> bool:
        """
        Authenticate and accept WebSocket connection.
        Returns True if authenticated, False otherwise.
        """
        try:
            # Validate JWT token from query params or headers
            if token and token.lower().startswith("bearer "):
                token = token.split(" ", 1)[1].strip()

            if not token:
                logger.warning("WebSocket connection rejected: missing token")
                await websocket.close(code=1008, reason="Authentication required")
                return False

            # Validate token using JWTIssuer
            from server.modules.auth.jwt_issuer import JWTIssuer, TokenRevokedError
            try:
                payload = await JWTIssuer.verify_token(token)
            except TokenRevokedError:
                logger.warning("WebSocket connection rejected: token revoked")
                await websocket.close(code=1008, reason="Token revoked")
                return False
            except Exception as e:
                logger.warning(f"WebSocket connection rejected: invalid token - {e}")
                await websocket.close(code=1008, reason="Invalid token")
                return False

            # Accept connection with authentication metadata
            await websocket.accept()
            async with self._lock:
                self.active_connections[websocket] = {
                    "user_id": payload.get("sub"),
                    "account_id": payload.get("account_id"),
                    "role": payload.get("role"),
                    "authenticated_at": asyncio.get_event_loop().time(),
                }
            
            logger.info(f"Authenticated client connected: {len(self.active_connections)} active clients")
            return True

        except Exception as e:
            logger.error(f"Error in connect: {e}")
            try:
                await websocket.close(code=1011, reason="Internal error")
            except Exception:
                pass
            return False

    async def disconnect(self, websocket: WebSocket):
        """Safely remove a connection."""
        async with self._lock:
            if websocket in self.active_connections:
                del self.active_connections[websocket]
                logger.info(f"Client disconnected. Remaining: {len(self.active_connections)}")

    async def broadcast(self, message: Dict[str, Any], account_id: Optional[int] = None):
        """
        Broadcast message to all connected clients (or specific account).
        Uses asyncio.gather for parallel sending - much faster than sequential.
        """
        if not self.active_connections:
            return

        # Filter connections by account_id if provided
        connections_to_send = []
        async with self._lock:
            for conn, metadata in self.active_connections.items():
                if account_id is None or metadata.get("account_id") == account_id:
                    connections_to_send.append(conn)

        if not connections_to_send:
            return

        # Send in parallel using asyncio.gather
        send_tasks = []
        for connection in connections_to_send:
            task = asyncio.create_task(
                self._safe_send(connection, message)
            )
            send_tasks.append(task)

        # Wait for all sends to complete (with timeout)
        try:
            await asyncio.wait_for(
                asyncio.gather(*send_tasks, return_exceptions=True),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            logger.warning("Broadcast timeout - some messages may not have been sent")

    async def _safe_send(self, connection: WebSocket, message: Dict[str, Any]):
        """Safely send a message to a single connection."""
        try:
            await connection.send_json(message)
        except Exception as e:
            logger.debug(f"Failed to send to connection: {e}")
            await self.disconnect(connection)

    async def send_to_user(self, websocket: WebSocket, message: Dict[str, Any]):
        """Send message to specific user connection."""
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.debug(f"Failed to send to user: {e}")
            await self.disconnect(websocket)

    def get_connection_count(self, account_id: Optional[int] = None) -> int:
        """Get count of active connections (optionally filtered by account)."""
        if account_id is None:
            return len(self.active_connections)
        
        return sum(
            1 for meta in self.active_connections.values()
            if meta.get("account_id") == account_id
        )

# Global manager instance
ws_manager = ConnectionManager()
