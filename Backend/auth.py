# auth.py
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from passlib.hash import bcrypt

from db import get_db
import models, schemas

router = APIRouter(prefix="/auth", tags=["auth"])

def assign_wallet_from_pool(db: Session, user: models.User) -> str:
    """
    wallet_pool에서 아직 사용되지 않은 지갑 하나를 꺼내서
    해당 user에게 배정하고, user.wallet_address를 채워준다.
    """
    wallet = (
        db.query(models.WalletPool)
        .filter(models.WalletPool.is_used == False)  # 아직 안 쓴 지갑
        .order_by(models.WalletPool.created_at)
        .first()
    )

    if not wallet:
        # 여유 지갑이 없으면 500 에러
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="할당 가능한 지갑이 없습니다. 관리자에게 문의하세요.",
        )

    wallet.is_used = True
    wallet.assigned_user_id = user.id
    user.wallet_address = wallet.address

    db.add(wallet)
    db.add(user)

    return wallet.address


@router.post("/register", response_model=schemas.AuthUser)
def register(payload: schemas.RegisterRequest, db: Session = Depends(get_db)):
    # 1. username 또는 email 중복 확인
    existing = db.query(models.User).filter(
        (models.User.username == payload.username) |
        (models.User.email == payload.email)
    ).first()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="이미 사용 중인 아이디 또는 이메일입니다.",
        )

    # 2. 비밀번호 해시
    password_hash = bcrypt.hash(payload.password)

    # 3. User 생성 (role 포함)
    role = payload.role.upper() if payload.role else "USER"

    user = models.User(
        username=payload.username,
        password_hash=password_hash,
        nickname=payload.nickname,
        email=payload.email,
        role=role,
    )
    db.add(user)
    db.flush()  # user.id 생성되도록 (commit 전)

    # 4. 관리자라면 직접 입력한 wallet_address 사용
    if role == "ADMIN":
        if not payload.wallet_address:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="관리자는 지갑 주소를 반드시 입력해야 합니다.",
            )
        user.wallet_address = payload.wallet_address

    # 5. 일반 유저는 wallet_pool에서 자동 배정
    else:
        assign_wallet_from_pool(db, user)

    # 6. 저장
    db.commit()
    db.refresh(user)

    return user




@router.post("/login", response_model=schemas.AuthUser)
def login(payload: schemas.LoginRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(
        models.User.username == payload.username
    ).first()

    if not user or not bcrypt.verify(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="아이디 또는 비밀번호가 잘못되었습니다.",
        )

    return user