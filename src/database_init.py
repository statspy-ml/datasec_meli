#!/usr/bin/env python3
"""Database initialization script
Creates tables and sets up the database schema
"""

import asyncio
import os

from loguru import logger

from src.models.database_models import Base
from src.services.database import get_database_manager, init_database


async def init_db():
    """Initialize database and create tables"""
    try:
        logger.info("Starting database initialization...")

        # Initialize database manager
        db_manager = get_database_manager()
        logger.info(f"Using database: {'PostgreSQL' if db_manager.is_postgres else 'SQLite'}")

        # Create database if it doesn't exist (PostgreSQL only)
        if db_manager.is_postgres:
            success = await db_manager.create_database_if_not_exists()
            if not success:
                logger.error("Failed to create database")
                return False

        # Test connection
        connection_ok = await db_manager.test_connection()
        if not connection_ok:
            logger.error("Database connection test failed")
            return False

        # Initialize async engine and create tables
        await init_database()

        logger.info("Database initialization completed successfully!")
        return True

    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        return False

def init_db_sync():
    """Synchronous wrapper for database initialization"""
    return asyncio.run(init_db())

if __name__ == "__main__":
    success = init_db_sync()
    exit(0 if success else 1)

