"""
Database configuration and connection management
Supports both SQLite (development) and PostgreSQL (production)
"""

import os
import asyncio
from typing import Optional, Any, Dict, List
from urllib.parse import urlparse
from loguru import logger
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy import create_engine
import asyncpg
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

# Base for SQLAlchemy models
Base = declarative_base()

class DatabaseManager:
    """Manages database connections and operations"""
    
    def __init__(self):
        self.database_url = os.getenv("DATABASE_URL", "sqlite:///./datasec_challenge.db")
        self.is_postgres = self.database_url.startswith("postgresql://")
        self.engine = None
        self.async_engine = None
        self.SessionLocal = None
        self.AsyncSessionLocal = None
        
        logger.info(f"Database configured: {'PostgreSQL' if self.is_postgres else 'SQLite'}")
        
    def get_database_url(self) -> str:
        """Get the appropriate database URL"""
        if self.is_postgres:
            # Convert postgres:// to postgresql:// if needed
            if self.database_url.startswith("postgres://"):
                return self.database_url.replace("postgres://", "postgresql://")
            return self.database_url
        return self.database_url
    
    def get_async_database_url(self) -> str:
        """Get async database URL"""
        if self.is_postgres:
            url = self.get_database_url()
            if url.startswith("postgresql://"):
                return url.replace("postgresql://", "postgresql+asyncpg://")
        return self.database_url
    
    def init_sync_engine(self):
        """Initialize synchronous engine"""
        if self.engine is None:
            if self.is_postgres:
                self.engine = create_engine(
                    self.get_database_url(),
                    pool_pre_ping=True,
                    pool_size=10,
                    max_overflow=20
                )
            else:
                self.engine = create_engine(
                    self.database_url,
                    connect_args={"check_same_thread": False}
                )
            
            self.SessionLocal = sessionmaker(
                autocommit=False,
                autoflush=False,
                bind=self.engine
            )
            
        return self.engine
    
    async def init_async_engine(self):
        """Initialize asynchronous engine"""
        if self.async_engine is None:
            if self.is_postgres:
                self.async_engine = create_async_engine(
                    self.get_async_database_url(),
                    pool_pre_ping=True,
                    pool_size=10,
                    max_overflow=20
                )
            else:
                # SQLite doesn't support async with SQLAlchemy
                self.async_engine = create_async_engine(
                    f"sqlite+aiosqlite:///{self.database_url.replace('sqlite:///', '')}"
                )
            
            self.AsyncSessionLocal = async_sessionmaker(
                bind=self.async_engine,
                class_=AsyncSession,
                expire_on_commit=False
            )
        
        return self.async_engine
    
    def get_sync_session(self):
        """Get synchronous database session"""
        if self.SessionLocal is None:
            self.init_sync_engine()
        return self.SessionLocal()
    
    async def get_async_session(self):
        """Get asynchronous database session"""
        if self.AsyncSessionLocal is None:
            await self.init_async_engine()
        return self.AsyncSessionLocal()
    
    async def create_database_if_not_exists(self):
        """Create database if it doesn't exist (PostgreSQL only)"""
        if not self.is_postgres:
            return True
            
        try:
            # Parse database URL
            parsed = urlparse(self.database_url)
            db_name = parsed.path.lstrip('/')
            
            # Connect to postgres database to create our database
            admin_url = f"postgresql://{parsed.username}:{parsed.password}@{parsed.hostname}:{parsed.port}/postgres"
            
            # Try to connect to target database first
            try:
                conn = await asyncpg.connect(self.database_url)
                await conn.close()
                logger.info(f"Database '{db_name}' already exists")
                return True
            except asyncpg.exceptions.InvalidCatalogNameError:
                # Database doesn't exist, create it
                pass
            
            # Create database using psycopg2 (sync)
            admin_conn = psycopg2.connect(
                host=parsed.hostname,
                port=parsed.port,
                user=parsed.username,
                password=parsed.password,
                database='postgres'
            )
            admin_conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
            
            cursor = admin_conn.cursor()
            cursor.execute(f'CREATE DATABASE "{db_name}"')
            cursor.close()
            admin_conn.close()
            
            logger.info(f"Created database '{db_name}'")
            return True
            
        except Exception as e:
            logger.error(f"Error creating database: {e}")
            return False
    
    async def test_connection(self) -> bool:
        """Test database connection"""
        try:
            if self.is_postgres:
                conn = await asyncpg.connect(self.database_url)
                await conn.close()
            else:
                engine = self.init_sync_engine()
                with engine.connect() as conn:
                    conn.execute(sa.text("SELECT 1"))
            
            logger.info("Database connection successful")
            return True
            
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            return False
    
    def get_postgres_config(self) -> Dict[str, Any]:
        """Get PostgreSQL configuration from environment"""
        if not self.is_postgres:
            return {}
            
        parsed = urlparse(self.database_url)
        return {
            "host": parsed.hostname or "localhost",
            "port": parsed.port or 5432,
            "database": parsed.path.lstrip('/'),
            "user": parsed.username,
            "password": parsed.password
        }

# Global database manager instance
db_manager = DatabaseManager()

def get_database_manager() -> DatabaseManager:
    """Get the global database manager instance"""
    return db_manager

async def init_database():
    """Initialize database and create tables"""
    await db_manager.create_database_if_not_exists()
    await db_manager.init_async_engine()
    
    # Create tables using Base metadata
    if db_manager.is_postgres:
        async with db_manager.async_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    else:
        engine = db_manager.init_sync_engine()
        Base.metadata.create_all(engine)
    
    logger.info("Database initialized successfully")

def get_sync_session():
    """Get a synchronous database session"""
    return db_manager.get_sync_session()

async def get_async_session():
    """Get an asynchronous database session"""
    return await db_manager.get_async_session()