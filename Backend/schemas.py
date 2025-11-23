# schemas.py
from typing import Optional
from uuid import UUID
from pydantic import BaseModel, EmailStr

class RegisterRequest(BaseModel):
    username: str
    password: str
    nickname: str
    email: EmailStr
    role: Optional[str] = "USER"
    wallet_address: Optional[str] = None  # 관리자 지갑 주소 (선택 사항)

class LoginRequest(BaseModel):
    username: str
    password: str

class AuthUser(BaseModel):
    id: UUID          # 🔥 여기 str → UUID 로 변경
    username: str
    role: str
    nickname: str
    email: EmailStr
    wallet_address: Optional[str] = None

    class Config:
        orm_mode = True
    
