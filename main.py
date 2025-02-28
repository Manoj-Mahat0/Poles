from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Header, Cookie
from pydantic import BaseModel
from pymongo import MongoClient
import jwt, datetime, asyncio, os
from fastapi.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
from typing import Dict, Optional

# Load environment variables (Replace with actual values or set them in Vercel)
MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://Manoj:mcpyR6dp3UMKydQo@pole.1qyxr.mongodb.net/?retryWrites=true&w=majority&appName=Pole")
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")

# Initialize FastAPI app
app = FastAPI()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust this for security
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB Setup
client = MongoClient(MONGO_URI)
db = client["pole_management"]
users_collection = db["users"]
poles_collection = db["poles"]

# Create indexes for fast lookups
users_collection.create_index("username", unique=True)
poles_collection.create_index("pole_id", unique=True)

# Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Async Lock for Pole Activation
pole_locks = asyncio.Lock()

# Pydantic Models
class UserCreate(BaseModel):
    username: str
    password: str
    name: str
    phone: str

class UserLogin(BaseModel):
    username: str
    password: str

class PoleControl(BaseModel):
    pole_id: int
    time_sec: int

# Utility Functions
def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: datetime.timedelta) -> str:
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")

def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(authorization: Optional[str] = Header(None), token_cookie: Optional[str] = Cookie(None)):
    token = authorization.split(" ")[1] if authorization and authorization.startswith("Bearer ") else token_cookie
    if not token:
        raise HTTPException(status_code=401, detail="Invalid or missing token")
    
    payload = decode_access_token(token)
    user = users_collection.find_one({"username": payload["sub"]}, {"_id": 0, "password": 0})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"username": user["username"], "name": user["name"], "phone": user["phone"]}

# Authentication Routes
@app.post("/signup")
async def signup(user: UserCreate):
    if users_collection.find_one({"username": user.username}):
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_password = get_password_hash(user.password)
    users_collection.insert_one({
        "username": user.username,
        "password": hashed_password,
        "name": user.name,
        "phone": user.phone
    })
    return {"message": "User created successfully"}

@app.post("/login")
async def login(user: UserLogin):
    db_user = users_collection.find_one({"username": user.username})
    if not db_user or not verify_password(user.password, db_user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_access_token({"sub": user.username}, datetime.timedelta(hours=1))
    return {"access_token": token, "token_type": "bearer"}

@app.get("/me")
async def user_info(user: dict = Depends(get_current_user)):
    return user

@app.get("/user")
async def get_username(user: dict = Depends(get_current_user)):
    return {"username": user["username"]}

# Pole Activation Logic
async def deactivate_pole_after_delay(pole_id: int, delay: int):
    await asyncio.sleep(delay)
    async with pole_locks:
        poles_collection.update_one({"pole_id": pole_id}, {"$set": {"active": False, "end_time": None}})

@app.post("/activate_pole")
async def activate_pole(pole: PoleControl, background_tasks: BackgroundTasks):
    end_time = datetime.datetime.utcnow() + datetime.timedelta(seconds=pole.time_sec)
    async with pole_locks:
        poles_collection.update_one(
            {"pole_id": pole.pole_id},
            {"$set": {"active": True, "end_time": end_time.isoformat()}},
            upsert=True
        )
    
    background_tasks.add_task(deactivate_pole_after_delay, pole.pole_id, pole.time_sec)
    return {"message": f"Pole {pole.pole_id} activated until {end_time.isoformat()}"}

@app.post("/deactivate_pole/{pole_id}")
async def deactivate_pole(pole_id: int):
    async with pole_locks:
        pole = poles_collection.find_one({"pole_id": pole_id})
        if not pole or not pole.get("active", False):
            raise HTTPException(status_code=400, detail="Pole is already deactivated or does not exist")
        
        poles_collection.update_one({"pole_id": pole_id}, {"$set": {"active": False, "end_time": None}})
    
    return {"message": f"Pole {pole_id} manually deactivated"}

@app.get("/pole_status")
async def get_pole_status():
    active_poles = {
        pole["pole_id"]: {"active": pole["active"], "end_time": pole["end_time"] if pole["active"] else None}
        for pole in poles_collection.find({}, {"_id": 0})
    }
    return active_poles

# ASGI Handler for Vercel
def handler(req, res):
    return app
