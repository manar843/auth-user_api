from fastapi import FastAPI, Depends, HTTPException, status, APIRouter
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import JWTError, jwt
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
import os
from dotenv import load_dotenv
from enum import Enum as PyEnum 

# Load environment variables
load_dotenv()

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:m12345@localhost/legal_chatbot")

# SQLAlchemy setup
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Security configuration
SECRET_KEY = os.getenv("SECRET_KEY", "mnmnhfff")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# FastAPI app
app = FastAPI(title="Legal Chatbot API", version="1.0.0")

# Enums
class RoleEnum(str, PyEnum):
    CLIENT = "client"
    LAWYER = "lawyer"

class PlanNameEnum(str, PyEnum): 
    MONTHLY = "Monthly Plan"
    ANNUALLY = "Annually Plan"
    PREMIUM = "Premium Plan"

class PaymentStatusEnum(str, PyEnum):
    SUCCESSFUL = "Successful"
    FAILED = "Failed"
    PENDING = "Pending"

# SQLAlchemy Models
class DBUser(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String(50))
    last_name = Column(String(50))
    email = Column(String(100), unique=True, index=True)
    phone_number = Column(String(20))
    password = Column(String)
    role = Column(Enum(RoleEnum))
    license_number = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    subscriptions = relationship("Subscription", back_populates="user")
    queries = relationship("Query", back_populates="user")

class Subscription(Base):
    __tablename__ = "subscriptions"

    id = Column(Integer, primary_key=True, index=True)
    plan_name = Column(Enum(PlanNameEnum))
    price = Column(Float)
    start_date = Column(DateTime)
    end_date = Column(DateTime)
    status = Column(String(20))
    user_id = Column(Integer, ForeignKey("users.id"))
    
    user = relationship("DBUser", back_populates="subscriptions")
    payments = relationship("Payment", back_populates="subscription")

class Payment(Base):
    __tablename__ = "payments"

    id = Column(Integer, primary_key=True, index=True)
    amount = Column(Float)
    currency = Column(String(10))
    created_at = Column(DateTime, default=datetime.utcnow)
    payment_status = Column(Enum(PaymentStatusEnum))
    payment_method = Column(String(50))
    subscription_id = Column(Integer, ForeignKey("subscriptions.id"))
    
    subscription = relationship("Subscription", back_populates="payments")

class Chat(Base):
    __tablename__ = "chats"

    id = Column(Integer, primary_key=True, index=True)
    status = Column(String(20))
    started_at = Column(DateTime, default=datetime.utcnow)
    ended_at = Column(DateTime, nullable=True)
    
    queries = relationship("Query", back_populates="chat")
    responses = relationship("Response", back_populates="chat")
    legal_docs = relationship("LegalDoc", back_populates="chat")
    chat_logs = relationship("ChatLog", back_populates="chat")

class Query(Base):
    __tablename__ = "queries"

    id = Column(Integer, primary_key=True, index=True)
    query_text = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey("users.id"))
    chat_id = Column(Integer, ForeignKey("chats.id"))
    
    user = relationship("DBUser", back_populates="queries")
    chat = relationship("Chat", back_populates="queries")
    responses = relationship("Response", back_populates="query")

class Response(Base):
    __tablename__ = "responses"

    id = Column(Integer, primary_key=True, index=True)
    response_text = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    generated_by = Column(String(50))
    query_id = Column(Integer, ForeignKey("queries.id"))
    chat_id = Column(Integer, ForeignKey("chats.id"))
    
    query = relationship("Query", back_populates="responses")
    chat = relationship("Chat", back_populates="responses")

class ChatLog(Base):
    __tablename__ = "chat_logs"

    id = Column(Integer, primary_key=True, index=True)
    session_start = Column(DateTime)
    session_end = Column(DateTime)
    chat_id = Column(Integer, ForeignKey("chats.id"))
    
    chat = relationship("Chat", back_populates="chat_logs")

class LegalDoc(Base):
    __tablename__ = "legal_docs"

    id = Column(Integer, primary_key=True, index=True)
    doc_name = Column(String(100))
    doc_type = Column(String(50))
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    chat_id = Column(Integer, ForeignKey("chats.id"))
    
    chat = relationship("Chat", back_populates="legal_docs")

# Create tables
Base.metadata.create_all(bind=engine)

# Pydantic models
class UserBase(BaseModel):
    email: EmailStr
    first_name: str
    last_name: str
    phone_number: Optional[str] = None

class UserCreate(UserBase):
    password: str
    role: RoleEnum
    license_number: Optional[str] = None

class UserResponse(UserBase):
    id: int
    role: RoleEnum
    created_at: datetime

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

class SubscriptionBase(BaseModel):
    plan_name: PlanNameEnum
    price: float
    start_date: datetime
    end_date: datetime
    status: str

class SubscriptionCreate(SubscriptionBase):
    pass

class SubscriptionResponse(SubscriptionBase):
    id: int
    user_id: int

    class Config:
        from_attributes = True

class PaymentBase(BaseModel):
    amount: float
    currency: str
    payment_status: PaymentStatusEnum
    payment_method: str

class PaymentCreate(PaymentBase):
    pass

class PaymentResponse(PaymentBase):
    id: int
    subscription_id: int
    created_at: datetime

    class Config:
        from_attributes = True

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Utility functions
def get_user_by_email(db: Session, email: str):
    return db.query(DBUser).filter(DBUser.email == email).first()

def create_user(db: Session, user: UserCreate):
    hashed_password = pwd_context.hash(user.password)
    db_user = DBUser(
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        phone_number=user.phone_number,
        password=hashed_password,
        role=user.role,
        license_number=user.license_number
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def authenticate_user(db: Session, email: str, password: str):
    user = get_user_by_email(db, email)
    if not user:
        return False
    if not pwd_context.verify(password, user.password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    
    user = get_user_by_email(db, token_data.email)
    if user is None:
        raise credentials_exception
    return user

# Authentication APIs
@app.post("/register", response_model=UserResponse)
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = get_user_by_email(db, user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    return create_user(db, user)

@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/logout")
def logout(token: str = Depends(oauth2_scheme)):
    return {"message": "Successfully logged out"}

# User APIs
@app.get("/users/{user_id}", response_model=UserResponse)
def get_user(
    user_id: int, 
    current_user: DBUser = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.id != user_id and current_user.role != RoleEnum.LAWYER:
        raise HTTPException(status_code=403, detail="Not authorized to access this user")
    
    user = db.query(DBUser).filter(DBUser.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@app.put("/users/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int, 
    update_data: UserBase, 
    current_user: DBUser = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to update this user")
    
    user = db.query(DBUser).filter(DBUser.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    for field, value in update_data.dict(exclude_unset=True).items():
        setattr(user, field, value)
    
    db.commit()
    db.refresh(user)
    return user

@app.get("/users/{user_id}/subscription", response_model=SubscriptionResponse)
def get_user_subscription(
    user_id: int, 
    current_user: DBUser = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.id != user_id and current_user.role != RoleEnum.LAWYER:
        raise HTTPException(status_code=403, detail="Not authorized to access this subscription")
    
    subscription = (
        db.query(Subscription)
        .filter(Subscription.user_id == user_id)
        .order_by(Subscription.end_date.desc())
        .first()
    )
    if not subscription:
        raise HTTPException(status_code=404, detail="Subscription not found")
    return subscription

# Subscription APIs
@app.get("/subscriptions", response_model=List[SubscriptionResponse])
def get_subscriptions(
    current_user: DBUser = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    subscriptions = db.query(Subscription).all()
    return subscriptions

@app.post("/subscriptions", response_model=SubscriptionResponse)
def create_subscription(
    subscription_data: dict,  # تغيير هنا لاستقبال dict بدلاً من نموذجين منفصلين
    current_user: DBUser = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        subscription = subscription_data["subscription"]
        payment = subscription_data["payment"]
        
        db_subscription = Subscription(
            plan_name=subscription["plan_name"],
            price=subscription["price"],
            start_date=subscription["start_date"],
            end_date=subscription["end_date"],
            status=subscription["status"],
            user_id=current_user.id
        )
        db.add(db_subscription)
        db.commit()
        db.refresh(db_subscription)
        
        db_payment = Payment(
            amount=payment["amount"],
            currency=payment["currency"],
            payment_status=payment["payment_status"],
            payment_method=payment["payment_method"],
            subscription_id=db_subscription.id
        )
        db.add(db_payment)
        db.commit()
        
        return db_subscription
    except KeyError as e:
        raise HTTPException(status_code=400, detail=f"Missing required field: {str(e)}")

@app.put("/subscriptions/{sub_id}", response_model=SubscriptionResponse)
def update_subscription(
    sub_id: int,
    status: str,
    current_user: DBUser = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    subscription = db.query(Subscription).filter(
        Subscription.id == sub_id,
        Subscription.user_id == current_user.id
    ).first()
    
    if not subscription:
        raise HTTPException(status_code=404, detail="Subscription not found")
    
    subscription.status = status
    db.commit()
    db.refresh(subscription)
    return subscription