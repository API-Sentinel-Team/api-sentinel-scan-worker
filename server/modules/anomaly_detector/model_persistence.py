"""
ML Model Persistence Module.
Stores trained anomaly detection models in the database for reuse across server restarts.
"""
import pickle
import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from server.models.core import ThreatConfig
import logging

logger = logging.getLogger(__name__)

class ModelPersistence:
    """
    Manages storage and retrieval of trained ML models to/from database.
    Uses ThreatConfig table with JSON blob storage for model data.
    """
    
    @staticmethod
    async def save_model(
        db: AsyncSession,
        account_id: int,
        model_name: str,
        model_data: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Save a trained model to the database.
        
        Args:
            db: Database session
            account_id: Tenant/account ID
            model_name: Unique name for the model (e.g., 'isolation_forest_v1')
            model_data: Serialized model data (dict with 'model_bytes' and 'scaler')
            metadata: Optional metadata (training_samples, accuracy, etc.)
        
        Returns:
            True if saved successfully
        """
        try:
            # Get or create ThreatConfig for the account
            result = await db.execute(
                select(ThreatConfig).where(ThreatConfig.account_id == account_id)
            )
            config = result.scalar_one_or_none()
            
            if config is None:
                config = ThreatConfig(account_id=account_id)
                db.add(config)
            
            # Initialize model_store if not exists
            if not hasattr(config, 'model_store') or config.model_store is None:
                config.model_store = {}
            
            # Store the model with timestamp
            config.model_store[model_name] = {
                "data": model_data,
                "metadata": metadata or {},
                "saved_at": datetime.now(timezone.utc).isoformat(),
                "account_id": account_id,
            }
            
            # Also store in ratelimit_config for compatibility
            if config.ratelimit_config is None:
                config.ratelimit_config = {}
            config.ratelimit_config[f"model_{model_name}"] = {
                "saved_at": datetime.now(timezone.utc).isoformat(),
                "has_model": True,
            }
            
            await db.commit()
            logger.info(f"Model '{model_name}' saved for account {account_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save model '{model_name}': {e}")
            await db.rollback()
            return False

    @staticmethod
    async def load_model(
        db: AsyncSession,
        account_id: int,
        model_name: str
    ) -> Optional[Dict[str, Any]]:
        """
        Load a trained model from the database.
        
        Args:
            db: Database session
            account_id: Tenant/account ID
            model_name: Name of the model to load
        
        Returns:
            Model data dict or None if not found
        """
        try:
            result = await db.execute(
                select(ThreatConfig).where(ThreatConfig.account_id == account_id)
            )
            config = result.scalar_one_or_none()
            
            if config is None or not config.model_store:
                return None
            
            model_info = config.model_store.get(model_name)
            if model_info:
                logger.info(f"Model '{model_name}' loaded for account {account_id}")
                return model_info
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to load model '{model_name}': {e}")
            return None

    @staticmethod
    async def delete_model(
        db: AsyncSession,
        account_id: int,
        model_name: str
    ) -> bool:
        """
        Delete a model from the database.
        
        Args:
            db: Database session
            account_id: Tenant/account ID
            model_name: Name of the model to delete
        
        Returns:
            True if deleted successfully
        """
        try:
            result = await db.execute(
                select(ThreatConfig).where(ThreatConfig.account_id == account_id)
            )
            config = result.scalar_one_or_none()
            
            if config is None or not config.model_store:
                return False
            
            if model_name in config.model_store:
                del config.model_store[model_name]
                await db.commit()
                logger.info(f"Model '{model_name}' deleted for account {account_id}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to delete model '{model_name}': {e}")
            await db.rollback()
            return False

    @staticmethod
    async def list_models(
        db: AsyncSession,
        account_id: int
    ) -> Dict[str, Dict[str, Any]]:
        """
        List all saved models for an account.
        
        Args:
            db: Database session
            account_id: Tenant/account ID
        
        Returns:
            Dict of model_name -> metadata
        """
        try:
            result = await db.execute(
                select(ThreatConfig).where(ThreatConfig.account_id == account_id)
            )
            config = result.scalar_one_or_none()
            
            if config is None or not config.model_store:
                return {}
            
            models = {}
            for name, info in config.model_store.items():
                models[name] = {
                    "saved_at": info.get("saved_at"),
                    "metadata": info.get("metadata", {}),
                }
            
            return models
            
        except Exception as e:
            logger.error(f"Failed to list models for account {account_id}: {e}")
            return {}
