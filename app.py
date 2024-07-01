'''References
1) https://fastapi.tiangolo4.com/
2) https://fastapi.tiangolo.com/tutorial/security/
3) https://fastapi.tiangolo.com/tutorial/sql-databases/
'''
# Import the required modules
from fastapi import FastAPI, HTTPException, Depends, status, Security
from pydantic import BaseModel, ValidationError
# sqlalchemy parts
from sqlalchemy import create_engine, Column, Integer, String, DateTime, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
# Regex
from dotenv import dotenv_values
import re
import json
# Imprts for authentication
from datetime import datetime, timedelta, timezone
from typing import Annotated
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, SecurityScopes
from passlib.context import CryptContext
from jose import JWTError, jwt

# Function to validate name using regex
def valid_name(name):
    # Allow for <first middle last>, <first last>, <last, first MI>
    pattern = r"^[a-zA-Z]{2,}$|[a-zA-Z]{2,}\s([A-Z]([a-z]+|\.)\s)?[a-zA-Z]{1,}([’']?[a-zA-Z]{2,}-?[a-zA-Z]{2,}|-?[a-zA-Z]{2,})$|^[a-zA-Z]{1,}([’']?[a-zA-Z]{2,}-?[a-zA-Z]{2,}|-?[a-zA-Z]{2,}),\s[a-zA-Z]{2,}(\s[A-Z]([a-z]+|\.))?$"
    match = re.match(pattern, name)
    if match:
        return True
    else:
        return False
    
# Function to validate phone number using regex
def valid_phone_number(phone_number):
    pattern = r"^\d{5}([\.\s]\d{5})?$|^(\+?\d{0,2}[\s\.])?\d{2}[\s\.]\d{2}[\s\.]\d{2}[\s\.]\d{2}$|^(\+?\d{0,2}[\s\.])?\d{4}[\s\.]\d{4}$|^\d{3}[-\.]\d{4}$|^(\+?1[-\s\.]?)?(\(\d{3}\)|\d{3}[\.\s-])\d{3}[\.\s-]\d{4}$|^(\+?\d{1,2}\s)?\(?\d{1,2}\)?[\s.-]\d{3}[\s.-]\d{4}$|^\d{0,3}\s(\d{1,3}\s)?\d{3}\s\d{3}\s\d{4}$"
    match = re.match(pattern, phone_number)
    if match:
        return True
    else:
        return False

# Create the FastAPI app
app = FastAPI()

# Load the configuration file
# couldnt manage to use a .env file on docker so i used a json file 
'''config = dotenv_values(".env")
sqlite_pb = config["db"]
SECRET_KEY = config["secret"]
ALGORITHM = config["algorithm"]
ACCESS_TOKEN_EXPIRE_MINUTES = int(config["expiration"])'''
with open("config.json") as f:
    config = json.load(f)
sqlite_pb = config["database"]["db"]
SECRET_KEY = config["auth"]["secret"]
ALGORITHM = config["auth"]["algorithm"]
ACCESS_TOKEN_EXPIRE_MINUTES = int(config["auth"]["expiration"])

# Create the database engines
pb_engine = create_engine(sqlite_pb, echo=True)

# Create the base class for the database models
Base = declarative_base()

# Create the PhoneBook model class
class PhoneBook(Base):
    __tablename__ = "phonebook"

    id = Column(Integer, primary_key=True)
    full_name = Column(String)
    phone_number = Column(String)
    
# Create the Logging model class
class Logging(Base):
    __tablename__ = "logging"

    id = Column(Integer, primary_key=True)
    full_name = Column(String)
    phone_number = Column(String)
    log_time = Column(DateTime(timezone=True), server_default=func.now())
    log_message = Column(String)

# Create the Users model class
class Users(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String)
    full_name = Column(String)
    phone_number = Column(String)
    hashed_password = Column(String)
    disabled = Column(String)

# Create the database schema
Base.metadata.create_all(pb_engine)

# Create the session class for database operations
pb_session = sessionmaker(bind=pb_engine)

# Create the Pydantic model class for request and response data
class Person(BaseModel):
    full_name: str
    phone_number: str

#Authentication--------------------------------------------------------------------------------------------#
#Code for authentication was obtained and altered for the given requirements ------------------------------#
#https://fastapi.tiangolo.com/advanced/security/oauth2-scopes/ --------------------------------------------#
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None
    scopes: list[str] = []

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Authentication
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token",
    # three scopes: read, write, user. these will be the roles as per the requirements
    scopes={"read": "Only allow calls to list.", "write": "Can call add and remove.", "user":"Read info about current user."},)

# Create User class for authentication
class User(BaseModel):
    username: str
    full_name: str | None = None
    phone_number: str | None = None
    disabled: bool | None = None

class UserInDB(User):
    hashed_password: str

def get_password_hash(password):
    return pwd_context.hash(password)
    
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user(username: str):
    # Check if the username exists in the database
    session=pb_session()
    user = session.query(Users).filter_by(username=username).first()
    session.close()
    if user:
        return UserInDB(**user.__dict__)
    
def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(
    security_scopes: SecurityScopes,token: Annotated[str, Depends(oauth2_scheme)]
):
    if security_scopes.scopes:
        authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
    else:
        authenticate_value = "Bearer"
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": authenticate_value},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_scopes = payload.get("scopes", [])
        token_data = TokenData(scopes=token_scopes, username=username)
    except (JWTError, ValidationError):
        raise credentials_exception
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    # Verify that all the scopes required, by this dependency and all the dependants
    for scope in security_scopes.scopes:
        if scope not in token_data.scopes:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not enough permissions",
                headers={"WWW-Authenticate": authenticate_value},
            )
    return user

# Check if the user is active 
async def get_current_active_user(
    current_user: Annotated[User, Security(get_current_user, scopes=["user"])],
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# Create a route to get the token and give access to the user
@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "scopes": form_data.scopes},
        expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")

# Route to get the current user details. needs to be authenticated and active (more of a debug route)
@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: Annotated[User, Depends(get_current_active_user)]):
    return current_user

#----------------------------------------------------------------------------------------------------------#
#PHONEBOOK-API-Paths---------------------------------------------------------------------------------------#
#----------------------------------------------------------------------------------------------------------#

# Define the API endpoints
@app.get("/PhoneBook/list")
def list_phonebook(current_user: Annotated[User, Security(get_current_active_user, scopes=["read"])]):
    # If the user is authenticated and has the correct scope (read role), list all the records in the phonebook
    if current_user:
        # Make a session for logging
        session = pb_session()
        # Make a new log entry
        new_log = Logging(log_message=f'{current_user.full_name} listed the phonebook')
        session.add(new_log)
        session.commit()
        session.close()
        # Make a session for listing phonebook
        session = pb_session()
        # Query all the records in the phonebook table
        phonebook = session.query(PhoneBook).all()
        session.close()
    # Return the list of records as JSON objects
    return phonebook

@app.post("/PhoneBook/add")
def add_person(person: Person, current_user: Annotated[User, Security(get_current_active_user, scopes=["read","write"])]):
    # If the user is authenticated and has the correct scopes (read and write role), list all the records in the phonebook
    if current_user:
        # Get a new session
        session = pb_session()

        # Validate the full name and phone number and raise an exception if invalid
        if not valid_name(person.full_name):
            session.close()
            raise HTTPException(status_code=400, detail="Invalid format. Please try entering a valid name.")
        if not valid_phone_number(person.phone_number):
            session.close()
            raise HTTPException(status_code=400, detail="Invalid format. Please try entering a valid phone number.")
        
        # Check if the person already exists in the database by phone number
        existing_number = session.query(PhoneBook).filter_by(phone_number=person.phone_number).first()
        if existing_number:
            session.close()
            raise HTTPException(status_code=400, detail="Phone number already exists. Please try entering a different number.")
        
        # Check if the person already exists in the database by name
        existing_person = session.query(PhoneBook).filter_by(full_name=person.full_name).first()
        if existing_person:
            session.close()
            raise HTTPException(status_code=400, detail="Person already exists. Please try entering a different name.")
        
        # Otherwise, create a new PhoneBook record and add it to the database
        new_person = PhoneBook(full_name=person.full_name, phone_number=person.phone_number)
        session.add(new_person)
        session.commit()
        # Close the session
        session.close()

        # Make a session for logging
        session = pb_session()
        # Make a new log entry
        new_log = Logging(full_name=person.full_name, phone_number=person.phone_number, log_message=f'{current_user.full_name} added a new entry')
        session.add(new_log)
        session.commit()
        session.close()
    # Return a success message
    return {"message": "Person added successfully"}

@app.put("/PhoneBook/deleteByName")
def delete_by_name(full_name: str, current_user: Annotated[User, Security(get_current_active_user, scopes=["read","write"])]):
    # If the user is authenticated and has the correct scopes (read and write role), list all the records in the phonebook
    if current_user:
        # Get a new session
        session = pb_session()

        # Validate the full name and raise an exception if invalid
        if not valid_name(full_name):
            session.close()
            raise HTTPException(status_code=400, detail="Invalid format. Please try entering a valid name.")
        
        # Query the person by name in the database
        person = session.query(PhoneBook).filter_by(full_name=full_name).first()
        # If the person does not exist, raise an exception
        if not person:
            session.close()
            raise HTTPException(status_code=404, detail="Person not found in the database")
        
        # Otherwise, delete the person from the database
        session.delete(person)
        session.commit()
        # Close the session
        session.close()

        # Make a session for logging
        session = pb_session()
        # Make a new log entry
        new_log = Logging(full_name=full_name, phone_number=person.phone_number, log_message=f'{current_user.full_name} deleted entry by name')
        session.add(new_log)
        session.commit()
        session.close()
    # Return a success message
    return {"message": "Person deleted successfully"}

@app.put("/PhoneBook/deleteByNumber")
def delete_by_number(phone_number: str, current_user: Annotated[User, Security(get_current_active_user, scopes=["read","write"])]):
    # If the user is authenticated and has the correct scopes (read and write role), list all the records in the phonebook
    if current_user:
        # Get a new session
        session = pb_session()

        # Validate the phone number and raise an exception if invalid
        if not valid_phone_number(phone_number):
            session.close()
            raise HTTPException(status_code=400, detail="Invalid format. Please try entering a valid phone number.")
        
        # Query the person by phone number in the database
        person = session.query(PhoneBook).filter_by(phone_number=phone_number).first()
        # If the person does not exist, raise an exception
        if not person:
            session.close()
            raise HTTPException(status_code=404, detail="Person not found in the database")
        
        # Otherwise, delete the person from the database
        session.delete(person)
        session.commit()
        # Close the session
        session.close()

        # Make a session for logging
        session = pb_session()
        # Make a new log entry
        new_log = Logging(full_name=person.full_name, phone_number=phone_number, log_message=f'{current_user.full_name} deleted entry by number')
        session.add(new_log)
        session.commit()
    # Return a success message
    return {"message": "Person deleted successfully"}