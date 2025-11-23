# db.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# ★ 일단은 하드코딩으로 정확히 맞춰보자
DB_USER = "campusbadge_user"
DB_PASS = "supersecret"
DB_NAME = "campusbadge"
DB_HOST = "127.0.0.1"  # Docker에서 5432:5432 열어놨으니까 로컬에서 이렇게 접속
DB_PORT = "5432"

DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

engine = create_engine(DATABASE_URL, echo=True, future=True)
#                     ↑ echo=True 로 쿼리 로그도 보이게 (디버깅 편하게)

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
