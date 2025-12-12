# main.py
from fastapi import FastAPI, HTTPException, Depends, File, UploadFile, Form
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, Session
import os
import shutil

# ---------- CONFIG ----------
SECRET_KEY = os.environ.get("SECRET_KEY", "dev_secret_change_me_please")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./budget_app.db")
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "./uploads")

# ensure upload dir exists
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ---------- DATABASE (SQLAlchemy) ----------
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(80), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)

class Expense(Base):
    __tablename__ = "expenses"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    amount = Column(Float, nullable=False)
    category = Column(String(120), nullable=False)
    vendor = Column(String(200), nullable=True)
    filename = Column(String(255), nullable=True)
    date = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# ---------- APP ----------
app = FastAPI(title="Smart Budget Tracker (Backend)")

# allow frontend origins - adjust if needed
origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost",
    "http://127.0.0.1",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins + ["*"],  # you can restrict "*" -> origins in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- AUTH HELPERS ----------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return token

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        sub = payload.get("sub")
        if sub is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.id == int(sub)).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user

# ---------- Pydantic Schemas ----------
class RegisterIn(BaseModel):
    username: str
    password: str

class TokenOut(BaseModel):
    access_token: str
    token_type: str

class ExpenseOut(BaseModel):
    id: int
    amount: float
    category: str
    vendor: Optional[str]
    filename: Optional[str]
    date: datetime

    class Config:
        orm_mode = True

# ---------- AUTH ENDPOINTS ----------
@app.post("/register")
def register(payload: RegisterIn, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    hashed = get_password_hash(payload.password)
    user = User(username=payload.username, hashed_password=hashed)
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"message": "User created", "user_id": user.id}

@app.post("/token", response_model=TokenOut)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = create_access_token({"sub": str(user.id)}, expires_delta=access_token_expires)
    return {"access_token": token, "token_type": "bearer"}

@app.get("/me")
def read_me(current_user: User = Depends(get_current_user)):
    return {"user_id": current_user.id, "username": current_user.username}

# ---------- EXPENSE ENDPOINTS ----------
@app.post("/expenses/upload_bill", response_model=ExpenseOut)
async def upload_bill(file: UploadFile = File(...), current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Accepts an uploaded file (bill/receipt). For demo we simulate OCR and categorization.
    Saves file in UPLOAD_DIR and creates an Expense record.
    """
    # save file
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    safe_name = f"{current_user.id}_{timestamp}_{file.filename}"
    dest_path = os.path.join(UPLOAD_DIR, safe_name)
    with open(dest_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # --- Simulated OCR & categorization logic ---
    # For demo: random-ish or fixed, but we can base on filename content
    lower = file.filename.lower()
    if "coffee" in lower or "cafe" in lower:
        category = "Food & Drink"
        amount = 4.5
        vendor = "Local Cafe"
    elif "grocery" in lower or "super" in lower:
        category = "Groceries"
        amount = 38.25
        vendor = "Grocery Store"
    elif "fuel" in lower or "petrol" in lower:
        category = "Transport"
        amount = 52.0
        vendor = "Fuel Station"
    else:
        # default simulated
        category = "Misc"
        amount = 25.75
        vendor = "Unknown Vendor"

    expense = Expense(
        user_id=current_user.id,
        amount=amount,
        category=category,
        vendor=vendor,
        filename=safe_name,
        date=datetime.utcnow()
    )
    db.add(expense)
    db.commit()
    db.refresh(expense)
    return expense

@app.get("/expenses", response_model=List[ExpenseOut])
def list_expenses(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    items = db.query(Expense).filter(Expense.user_id == current_user.id).order_by(Expense.date.desc()).all()
    return items

@app.get("/analytics/spending_by_category")
def get_spending_by_category(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(Expense).filter(Expense.user_id == current_user.id).all()
    totals = {}
    for e in rows:
        totals[e.category] = totals.get(e.category, 0.0) + float(e.amount)
    chart_data = [{"category": k, "total_spent": round(v, 2)} for k, v in totals.items()]
    return chart_data

# ---------- SUGGESTIONS ----------
@app.get("/suggestions")
def get_suggestions(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Returns simple, actionable suggestions based on user's spending categories.
    (Basic logic for demo purposes)
    """
    rows = db.query(Expense).filter(Expense.user_id == current_user.id).all()
    totals = {}
    count = {}
    for e in rows:
        totals[e.category] = totals.get(e.category, 0.0) + float(e.amount)
        count[e.category] = count.get(e.category, 0) + 1

    if not totals:
        return {"suggestions": ["No expenses yet — upload a receipt to get suggestions!"]}

    # Rank categories by spend
    sorted_cats = sorted(totals.items(), key=lambda x: x[1], reverse=True)
    top_cat, top_amount = sorted_cats[0]

    suggestions = []
    suggestions.append(f"Your top spending category is **{top_cat}** with total ₹{top_amount:.2f}.")

    # Add some generic suggestions per category
    if top_cat.lower().startswith("food") or top_cat.lower().startswith("grocer"):
        suggestions.append("Try planning weekly meals and buying in bulk — it can reduce grocery & food costs by ~10–20%.")
        suggestions.append("Check for subscriptions or recurring deliveries you can cancel or switch to cheaper options.")
    elif top_cat.lower().startswith("trans"):
        suggestions.append("Consider carpooling or using public transport for part of the week to cut transport costs.")
        suggestions.append("If fuel is high, compare fuel prices or look at local loyalty programs.")
    else:
        suggestions.append("Track small 'Misc' purchases — they add up. Consider a 48-hour rule for non-essential buys.")

    # Add simple budgeting tip
    total_spend = sum(totals.values())
    suggestions.append(f"Total across categories: ₹{total_spend:.2f}. Set a monthly target and track weekly to stay on budget.")

    return {"suggestions": suggestions}

# ---------- SIMPLE HEALTH CHECK ----------
@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.utcnow().isoformat()}
