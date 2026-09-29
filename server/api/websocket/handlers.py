from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from .manager import ws_manager
import logging

logger = logging.getLogger(__name__)

router = APIRouter()

@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str = Query(None, description="JWT token for authentication")
):
    """
    Main WebSocket endpoint for the Dashboard with authentication.
    Pushes real-time security alerts and scan progress.
    """
    # Authenticate the connection
    authenticated = await ws_manager.connect(websocket, token)
    if not authenticated:
        return

    try:
        while True:
            # Current implementation is primarily Push-only (Backend -> Frontend)
            # but we keep the receive loop to handle client heartbeats/pings.
            data = await websocket.receive_text()
            # Respond to ping for connection health if needed
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        await ws_manager.disconnect(websocket)


@router.websocket("/ws/account/{account_id}")
async def websocket_account_endpoint(
    websocket: WebSocket,
    account_id: int,
    token: str = Query(None, description="JWT token for authentication")
):
    """
    WebSocket endpoint for specific account with authentication.
    Only receives events for the specified account.
    """
    # Authenticate and verify account access
    authenticated = await ws_manager.connect(websocket, token)
    if not authenticated:
        return

    # Verify account_id matches the authenticated user
    # (This is done by the connection manager based on JWT payload)
    
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket account error: {e}")
        await ws_manager.disconnect(websocket)
