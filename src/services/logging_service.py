import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from loguru import logger
from sqlalchemy import and_, select
from sqlalchemy.exc import SQLAlchemyError

from src.models.base import AgentMessage
from src.models.database_models import AgentDecision, AgentInteraction, SessionModel
from src.services.database import get_database_manager, get_sync_session
from src.utils.json_utils import safe_json_dumps


class LoggingService:
    def __init__(self, db_path: str = "logs/agent_interactions.db"):
        self.db_path = db_path  # Keep for backward compatibility
        self.db_manager = get_database_manager()
        logger.info(f"LoggingService initialized with {'PostgreSQL' if self.db_manager.is_postgres else 'SQLite'}")

    def _clean_for_json_storage(self, obj: Any) -> Any:
        """Clean object recursively to make it JSON serializable for database storage"""
        from enum import Enum

        from pydantic import BaseModel

        # First, try to serialize the object as-is to see if it's already JSON-safe
        try:
            json.dumps(obj)
            return obj  # If it works, return as-is
        except (TypeError, ValueError):
            pass  # If it fails, continue with cleaning

        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, Enum):
            return obj.value
        if isinstance(obj, BaseModel):
            # Handle Pydantic models specifically
            try:
                # Use model_dump with mode='json' to get JSON-serializable data
                if hasattr(obj, "model_dump"):
                    dumped = obj.model_dump(mode="json")
                    return self._clean_for_json_storage(dumped)
                # Fallback for older Pydantic versions
                dumped = obj.dict()
                return self._clean_for_json_storage(dumped)
            except Exception as e:
                logger.warning(f"Failed to serialize Pydantic model: {e}")
                return str(obj)
        elif isinstance(obj, dict):
            cleaned_dict = {}
            for k, v in obj.items():
                if not k.startswith("_") and k not in ["__objclass__"]:
                    try:
                        cleaned_dict[k] = self._clean_for_json_storage(v)
                    except Exception:
                        # If cleaning fails, convert to string
                        cleaned_dict[k] = str(v)
            return cleaned_dict
        elif isinstance(obj, (list, tuple)):
            cleaned_list = []
            for item in obj:
                try:
                    cleaned_list.append(self._clean_for_json_storage(item))
                except Exception:
                    # If cleaning fails, convert to string
                    cleaned_list.append(str(item))
            return cleaned_list
        elif hasattr(obj, "__dict__"):
            try:
                clean_dict = {}
                for k, v in obj.__dict__.items():
                    if not k.startswith("_"):
                        try:
                            clean_dict[k] = self._clean_for_json_storage(v)
                        except Exception:
                            clean_dict[k] = str(v)
                return clean_dict
            except:
                return str(obj)
        else:
            # For any other type, try to convert to a JSON-safe type
            try:
                json.dumps(obj)
                return obj
            except (TypeError, ValueError):
                return str(obj)

    def _extract_essential_content(self, content: Any, message_type: str) -> Any:
        """Extract only essential information to persist, avoiding large complex objects"""
        # For report generation messages, extract only key metrics
        if message_type == "report_generation_complete":
            if isinstance(content, dict) and "report" in content:
                report = content["report"]
                if isinstance(report, dict):
                    # Extract only essential metrics, no complex nested objects
                    essential = {
                        "report_id": report.get("id", "unknown"),
                        "session_id": report.get("session_id", "unknown"),
                        "status": "completed",
                        "summary": {
                            "total_detectors": self._safe_extract(report, "total_detectors", 0),
                            "high_priority_count": self._safe_extract(report, "high_priority_count", 0),
                            "medium_priority_count": self._safe_extract(report, "medium_priority_count", 0),
                            "low_priority_count": self._safe_extract(report, "low_priority_count", 0),
                            "average_risk_score": self._safe_extract(report, "average_risk_score", 0.0),
                            "implementation_time": self._safe_extract(report, "estimated_implementation_time", "unknown"),
                        },
                        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "note": "Full report saved to file system, only summary persisted to database",
                    }
                    return {"essential_report": essential}

        # For other large content, apply size limits
        return self._apply_size_limits(content, max_size=5000)

    def _safe_extract(self, data: dict, key: str, default: Any) -> Any:
        """Safely extract value from dict, returning default if not found or problematic"""
        try:
            value = data.get(key, default)
            # Ensure value is JSON-safe
            import json
            json.dumps(value)
            return value
        except:
            return default

    def _apply_size_limits(self, content: Any, max_size: int = 5000) -> Any:
        """Apply size limits to content"""
        try:
            # Check current size
            content_str = json.dumps(content, default=str)
            if len(content_str) <= max_size:
                return content
        except:
            pass

        # Content too large, create summary
        if isinstance(content, dict):
            summary = {}
            for key, value in content.items():
                if isinstance(value, str):
                    summary[key] = value[:200] + "..." if len(value) > 200 else value
                elif isinstance(value, (list, tuple)):
                    summary[key] = f"[{len(value)} items]"
                elif isinstance(value, dict):
                    summary[key] = f"{{dict with {len(value)} keys}}"
                else:
                    summary[key] = str(value)[:100]

            summary["_truncated"] = True
            summary["_reason"] = "Content too large for database persistence"
            return summary
        return {
            "content_summary": str(content)[:1000] + "..." if len(str(content)) > 1000 else str(content),
            "_truncated": True,
        }

    async def _log_simple_summary(self, message: AgentMessage):
        """Log a simple summary for problematic messages"""
        try:
            # Create a simple, safe summary
            simple_content = {
                "message_type": message.message_type,
                "from_agent": message.from_agent.value,
                "to_agent": message.to_agent.value if message.to_agent else None,
                "status": "completed_but_content_too_complex_for_persistence",
                "session_id": message.session_id,
                "logged_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "note": "Original content contained complex objects unsuitable for JSON serialization",
            }

            with get_sync_session() as session:
                timestamp = message.timestamp
                if timestamp.tzinfo is None:
                    from datetime import timezone
                    timestamp = timestamp.replace(tzinfo=timezone.utc)

                interaction = AgentInteraction(
                    id=message.id,
                    session_id=message.session_id,
                    from_agent=message.from_agent.value,
                    to_agent=message.to_agent.value if message.to_agent else None,
                    message_type=message.message_type + "_summary",
                    content=simple_content,
                    timestamp=timestamp,
                )

                session.add(interaction)
                session.commit()

                logger.info(f"Logged simple summary: {message.from_agent.value} -> {message.to_agent}")

        except Exception as e:
            logger.warning(f"Even simple summary logging failed: {e}")
            # If even the summary fails, just log the attempt

    async def ensure_database_ready(self):
        """Ensure database is ready for operations"""
        try:
            await self.db_manager.create_database_if_not_exists()
            await self.db_manager.init_async_engine()
            return True
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            return False

    async def log_agent_interaction(self, message: AgentMessage):
        """Log agent-to-agent interactions using SQLAlchemy"""
        try:
            # Check if content can be safely serialized before processing
            try:
                import json
                # Test if content contains datetime objects
                json.dumps(message.content)
                content_safe = True
            except (TypeError, ValueError):
                content_safe = False

            # Skip problematic messages entirely to avoid serialization issues
            if not content_safe or message.message_type in ["report_generation_complete", "analysis_complete"]:
                logger.info(f"Skipped logging message '{message.message_type}' to avoid serialization issues")
                # Instead, log a simple summary
                await self._log_simple_summary(message)
                return

            # Extract only essential content to avoid serialization issues
            essential_content = self._extract_essential_content(message.content, message.message_type)

            # Clean the essential content for JSON storage
            clean_content = self._clean_for_json_storage(essential_content)

            # Simple validation since we're only storing essentials
            try:
                import json
                json.dumps(clean_content)
                logger.debug(f"Essential content validated for {message.message_type}")
            except Exception as e:
                logger.warning(f"Essential content still problematic, using minimal fallback: {e}")
                # Minimal fallback for essential data
                clean_content = {
                    "message_type": message.message_type,
                    "status": "essential_data_only",
                    "logged_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                }

            with get_sync_session() as session:
                # Ensure timestamp is timezone-aware for PostgreSQL
                timestamp = message.timestamp
                if timestamp.tzinfo is None:
                    from datetime import timezone
                    timestamp = timestamp.replace(tzinfo=timezone.utc)

                interaction = AgentInteraction(
                    id=message.id,
                    session_id=message.session_id,
                    from_agent=message.from_agent.value,
                    to_agent=message.to_agent.value if message.to_agent else None,
                    message_type=message.message_type,
                    content=clean_content,  # Use cleaned content for JSON storage
                    timestamp=timestamp,
                )

                session.add(interaction)
                session.commit()

                logger.info(f"Logged interaction: {message.from_agent.value} -> {message.to_agent}")

        except SQLAlchemyError as e:
            logger.error(f"Failed to log agent interaction: {e}")
            raise

    async def log_decision(self, decision_data: Dict[str, Any]):
        """Log agent decisions using SQLAlchemy"""
        try:
            # Clean data field to ensure JSON serialization works in PostgreSQL
            clean_data = self._clean_for_json_storage(decision_data.get("data", {}))

            with get_sync_session() as session:
                # Handle timestamp conversion and timezone
                timestamp = datetime.fromisoformat(decision_data["timestamp"]) if isinstance(decision_data["timestamp"], str) else decision_data["timestamp"]
                if timestamp.tzinfo is None:
                    from datetime import timezone
                    timestamp = timestamp.replace(tzinfo=timezone.utc)

                decision = AgentDecision(
                    agent=decision_data["agent"],
                    session_id=decision_data["session_id"],
                    decision=decision_data["decision"],
                    rationale=decision_data["rationale"],
                    data=clean_data,  # Use cleaned data for JSON storage
                    timestamp=timestamp,
                )

                session.add(decision)
                session.commit()

                logger.debug(f"Logged decision: {decision_data['agent']} - {decision_data['decision']}")

        except SQLAlchemyError as e:
            logger.error(f"Failed to log decision: {e}")
            raise

    def get_session_logs(self, session_id: str) -> Dict[str, List[Dict]]:
        """Get all logs for a specific session using SQLAlchemy"""
        try:
            with get_sync_session() as session:
                # Get interactions
                interactions_query = select(AgentInteraction).where(
                    AgentInteraction.session_id == session_id,
                ).order_by(AgentInteraction.timestamp)

                interactions_result = session.execute(interactions_query).scalars().all()
                interactions = []
                for interaction in interactions_result:
                    interactions.append({
                        "id": interaction.id,
                        "session_id": interaction.session_id,
                        "from_agent": interaction.from_agent,
                        "to_agent": interaction.to_agent,
                        "message_type": interaction.message_type,
                        "content": interaction.content,
                        "timestamp": interaction.timestamp.isoformat(),
                    })

                # Get decisions
                decisions_query = select(AgentDecision).where(
                    AgentDecision.session_id == session_id,
                ).order_by(AgentDecision.timestamp)

                decisions_result = session.execute(decisions_query).scalars().all()
                decisions = []
                for decision in decisions_result:
                    decisions.append({
                        "id": decision.id,
                        "agent": decision.agent,
                        "session_id": decision.session_id,
                        "decision": decision.decision,
                        "rationale": decision.rationale,
                        "data": decision.data or {},
                        "timestamp": decision.timestamp.isoformat(),
                    })

                return {
                    "interactions": interactions,
                    "decisions": decisions,
                }

        except SQLAlchemyError as e:
            logger.error(f"Failed to get session logs: {e}")
            return {"interactions": [], "decisions": []}

    def create_session(self, session_id: str, metadata: Dict[str, Any] = None):
        """Create a new session using SQLAlchemy"""
        try:
            # Clean metadata to ensure JSON serialization works in PostgreSQL
            clean_metadata = self._clean_for_json_storage(metadata or {})

            with get_sync_session() as session:
                new_session = SessionModel(
                    session_id=session_id,
                    session_metadata=clean_metadata,
                    status="active",
                )

                session.add(new_session)
                session.commit()

                logger.info(f"Created session: {session_id}")

        except SQLAlchemyError as e:
            logger.error(f"Failed to create session: {e}")
            raise

    def get_session_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session information"""
        try:
            with get_sync_session() as session:
                session_query = select(SessionModel).where(SessionModel.session_id == session_id)
                result = session.execute(session_query).scalar_one_or_none()

                if result:
                    return {
                        "session_id": result.session_id,
                        "created_at": result.created_at.isoformat(),
                        "status": result.status,
                        "metadata": result.session_metadata or {},
                        "ecosystem_description": result.ecosystem_description,
                        "completed_at": result.completed_at.isoformat() if result.completed_at else None,
                    }
                return None

        except SQLAlchemyError as e:
            logger.error(f"Failed to get session info: {e}")
            return None

    def update_session_status(self, session_id: str, status: str, ecosystem_description: str = None):
        """Update session status and optionally ecosystem description"""
        try:
            with get_sync_session() as session:
                session_query = select(SessionModel).where(SessionModel.session_id == session_id)
                session_obj = session.execute(session_query).scalar_one_or_none()

                if session_obj:
                    session_obj.status = status
                    if ecosystem_description:
                        session_obj.ecosystem_description = ecosystem_description
                    if status == "completed":
                        session_obj.completed_at = datetime.now()

                    session.commit()
                    logger.info(f"Updated session {session_id} status to {status}")

        except SQLAlchemyError as e:
            logger.error(f"Failed to update session status: {e}")
            raise

