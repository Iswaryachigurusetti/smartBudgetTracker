from sqlalchemy import Column, Integer, String, Float, DateTime
from database import Base
from datetime import datetime

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)
    hashed_password = Column(String(255))

class Expense(Base):
    __tablename__ = "expenses"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    amount = Column(Float)
    category = Column(String(100))
    vendor = Column(String(100))
    filename = Column(String(200))
    date = Column(DateTime, default=datetime.utcnow)
