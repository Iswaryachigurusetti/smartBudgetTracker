from fastapi import FastAPI, HTTPException, Depends, File, UploadFile
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Dict
from passlib.context import CryptContext
import jwt
from datetime import datetime, timedelta
import os
from collections import defaultdict
from fastapi.middleware.cors import CORSMiddleware
# Access the secret key from the environment variable set in .env
SECRET_KEY = os.environ.get("SECRET_KEY", "your_super_secret_jwt_key_1234567890_CHANGE_ME")

# --- CONFIGURATION (Authentication, simplified) ---
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI(title="Smart Budget Tracker API")

# Setup CORS to allow the frontend to communicate
origins = ["http://localhost:3000"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- IN-MEMORY 'DATABASE' (For quick demo) ---
# NOTE: This data resets when the API service restarts.
users_db: Dict[int, Dict] = {} 
expenses_db: List[Dict] = []
user_id_counter = 1
expense_id_counter = 1

# --- MODELS ---
class UserIn(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

# --- AUTH HELPERS (Same as before) ---
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid credentials")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    user_id = int(user_id)
    if user_id not in users_db:
         raise HTTPException(status_code=404, detail="User not found")
         
    return users_db[user_id]


# --- AUTH ENDPOINTS ---
@app.post("/register", tags=["Auth"])
def register_user(user_in: UserIn):
    global user_id_counter
    if any(u['username'] == user_in.username for u in users_db.values()):
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_password = get_password_hash(user_in.password)
    new_user = {
        "user_id": user_id_counter,
        "username": user_in.username,
        "hashed_password": hashed_password
    }
    users_db[user_id_counter] = new_user
    user_id_counter += 1
    return {"message": "User registered successfully"}

@app.post("/token", response_model=Token, tags=["Auth"])
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user_data = next((u for u in users_db.values() if u['username'] == form_data.username), None)

    if not user_data or not verify_password(form_data.password, user_data['hashed_password']):
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user_data['user_id'])}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


# --- EXPENSE & ANALYTICS ENDPOINTS ---
@app.post("/expenses/upload_bill", tags=["Expenses"])
async def upload_bill(
    file: UploadFile = File(...), 
    current_user: dict = Depends(get_current_user)
):
    """Simulated bill upload, OCR, and categorization."""
    global expense_id_counter
    
    # --- SIMULATED OCR & CATEGORIZATION ---
    simulated_ocr_data = {
        "amount": 25.75,
        "vendor": "Local Cafe",
        "date": datetime.now().isoformat(),
        "category": "Food & Drink" 
    }
    
    new_expense = {
        "expense_id": expense_id_counter,
        "user_id": current_user['user_id'],
        "amount": simulated_ocr_data["amount"],
        "category": simulated_ocr_data["category"],
        "date": datetime.fromisoformat(simulated_ocr_data["date"]),
        "vendor": simulated_ocr_data["vendor"],
        "filename": file.filename 
    }
    expenses_db.append(new_expense)
    expense_id_counter += 1
    
    return {"message": "Bill processed successfully (simulated)", "expense": new_expense}

@app.get("/analytics/spending_by_category", tags=["Analytics"])
def get_spending_by_category(current_user: dict = Depends(get_current_user)):
    """Generates data for the Pie/Donut chart visualization for the current user."""
    user_id = current_user['user_id']
    user_expenses = [e for e in expenses_db if e['user_id'] == user_id]
    
    category_totals = defaultdict(float)
    for expense in user_expenses:
        category_totals[expense['category']] += expense['amount']
        
    # Format for Chart.js
    chart_data = [{"category": cat, "total_spent": round(total, 2)} 
                  for cat, total in category_totals.items()]
    
    return chart_data