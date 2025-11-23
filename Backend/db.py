# db.py
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Render 환경변수에서 바로 가져오기
DATABASE_URL = os.environ.get("DATABASE_URL")

if not DATABASE_URL:
    # 로컬에서 테스트용으로 fallback 쓰고 싶으면 아래 두 줄 정도는 선택사항
    # DATABASE_URL = "postgresql://campusbadge_user:supersecret@127.0.0.1:5432/campusbadge"
    # 아니면 아예 강하게 에러 던져도 됨
    raise RuntimeError("DATABASE_URL env var is not set")

# Render에서 connection 끊김 방지용 옵션
engine = create_engine(DATABASE_URL, echo=True, future=True, pool_pre_ping=True)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
