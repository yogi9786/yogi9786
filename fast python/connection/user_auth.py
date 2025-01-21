from datetime import datetime, timedelta
from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi import HTTPException, status, Depends,APIRouter
from prisma import Prisma
from fastapi.security import OAuth2PasswordBearer
try:
    from connection.models import UserCreate  # type: ignore
except ImportError:
    raise ImportError("Cannot import UserCreate from connection.models. Ensure the module and class are correctly defined.")
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

# JWT Settings
SECRET_KEY = "your-secret-key-here"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
prisma = Prisma()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

from passlib.context import CryptContext
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12  # You can adjust the rounds for security/performance balance
)
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

@router.post("/register", tags=["Authentication"])
async def register(user: UserCreate):
    if user.password != user.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords don't match")
    
    hashed_password = get_password_hash(user.password)
    
    try:
        new_user = await prisma.user.create(data={
            'username': str(user.username),
            'email': str(user.email),
            'password': str(hashed_password)
        })
        return {"message": "User created successfully"}
    except Exception as e:
        raise HTTPException(
            status_code=400, 
            detail=f"Username or email already exists: {str(e)}"
        )

@router.post("/login", tags=["Authentication"])
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await prisma.user.find_first(
        where={
            'username': form_data.username
        }
    )
    
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

# Protected route example
@router.get("/me", tags=["Authentication"])
async def read_users_me(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    
    user = await prisma.user.find_first(
        where={
            'username': username
        }
    )
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"username": user.username, "email": user.email}


@router.post("/logout", tags=["Authentication"])
async def logout(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail="Invalid token"
            )
        
        # Since JWT is stateless, we'll return a success message
        # For enhanced security, you could implement a token blacklist
        return {
            "message": "Successfully logged out",
        }
        
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )