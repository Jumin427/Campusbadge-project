# models.py
import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, Text, DateTime, Boolean, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import declarative_base

Base = declarative_base()

def utc_now():
    # DB가 TIMESTAMPTZ(시간대 포함)이라서 timezone-aware로 맞춰줌
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(Text, nullable=False, unique=True)
    password_hash = Column(Text, nullable=False)
    role = Column(Text, nullable=False, default="USER")
    nickname = Column(Text, nullable=False)
    wallet_address = Column(Text, unique=True)
    email = Column(Text, nullable=False, unique=True)

    # 🔥 여기 두 줄이 핵심
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)

class WalletPool(Base):
    __tablename__ = "wallet_pool"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    address = Column(Text, nullable=False, unique=True)

    is_used = Column(Boolean, nullable=False, default=False)

    # 어느 유저에게 배정됐는지 (없으면 None)
    assigned_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    # 선택: 개인키를 암호화해서 저장하고 싶으면 사용 (지금은 안 써도 됨)
    encrypted_private_key = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
