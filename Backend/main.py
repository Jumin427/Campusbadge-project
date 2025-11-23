# main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import models
from db import engine
from auth import router as auth_router

app = FastAPI(title="CampusBadge Backend")

origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://192.168.0.13:5173",  # 같은 PC에서 IP로 접속할 가능성 대비
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# init.sql로 테이블 생성하니까 이건 선택 사항
# models.Base.metadata.create_all(bind=engine)

app.include_router(auth_router)

@app.get("/health")
def health_check():
    return {"status": "ok"}
