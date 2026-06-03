import logging
import traceback
import sqlite3
from datetime import datetime
from typing import Optional, Literal

from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from passlib.context import CryptContext

from services import M1, M2, LLMService


logging.basicConfig(
    filename="server.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger(__name__)

app = FastAPI(
    title="FortiSMB Hybrid Risk API",
    version="2.0.0",
    description="""
## Authentication System

This API supports **real Security Analyst authentication**.

### Signup
Create a new Security Analyst account.

Checks:
- Employee ID must be unique
- Email must be unique
- Password must be at least 8 characters
- Only **Security Analyst** role is allowed

### Login
Login using:
- **employee_id**
- **password**

Access:
- Only Security Analyst accounts can access FortiSMB mobile app.


---

## Entered Fields

This API receives one cybersecurity event and predicts its risk.

### Required fields
- **ai_query**: Natural-language AI request describing the event
- **action**: Event type such as `logon`, `file`, or `device`
- **fortismb_role**: User role in the FortiSMB system
- **hour**: Hour of event from `0` to `23`
- **off_hours**: Whether the event happened outside allowed working hours

### Optional fields
- **file_op**: File operation such as `read`, `write`, `copy`, `delete`
- **is_usb**: Whether USB/removable media was involved
- **date**: Event date string, optional

---

## Allowed Monitored Roles

FortiSMB tracks employee behavior for:

- **Administrative Employee**
- **Administrative Manager**
- **Contractor**
- **System Administrator**
- **Executive**

These are **tracked users**, not app login users.

---

## Prediction Flow

### Stage 1 — M1 (Random Forest)
Predicts:

- `Low`
- `Elevated`

### Stage 2 — M2 (XGBoost)
Runs only if Stage 1 is **Elevated**.

Predicts:

- `Medium`
- `High`

### LLM Explanation
Gemini generates a short explanation for the final risk result.

### Final System Actions

- **Low** → `Log & Monitor`
- **Medium** → `Alert & Verify`
- **High** → `Block & Mitigate`
"""
)

DB_NAME = "fortismb_users.db"

pwd_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    deprecated="auto"
)


def init_user_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            employee_id TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


init_user_db()

m1_service = M1()
m2_service = M2()
llm_service = LLMService()


class SignUpRequest(BaseModel):
    full_name: str
    employee_id: str
    email: str
    password: str
    role: str = "Security Analyst"


class LoginRequest(BaseModel):
    employee_id: str
    password: str


class QueryRequest(BaseModel):
    ai_query: str

    action: Literal[
        "logon",
        "file",
        "device"
    ]

    fortismb_role: Literal[
        "Administrative Employee",
        "Administrative Manager",
        "Contractor",
        "System Administrator",
        "Executive"
    ]

    file_op: Optional[str] = ""
    is_usb: bool = False

    hour: float = Field(
        ...,
        ge=0,
        le=23
    )

    off_hours: bool = False
    date: Optional[str] = None


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    logger.error(f"422 Validation Error | errors={exc.errors()}")

    return JSONResponse(
        status_code=422,
        content={
            "message": "Invalid input data",
            "errors": exc.errors()
        }
    )


@app.get("/")
def root():
    return {
        "message": "FortiSMB FastAPI is running"
    }


@app.post("/auth/signup")
def signup(request: SignUpRequest):
    try:
        if request.role != "Security Analyst":
            raise HTTPException(
                status_code=403,
                detail="Only Security Analyst accounts can be created."
            )

        if len(request.password) < 8:
            raise HTTPException(
                status_code=400,
                detail="Password must be at least 8 characters."
            )

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id FROM security_users WHERE employee_id = ?",
            (request.employee_id,)
        )

        if cursor.fetchone():
            conn.close()
            raise HTTPException(
                status_code=409,
                detail="Employee ID already exists."
            )

        cursor.execute(
            "SELECT id FROM security_users WHERE email = ?",
            (request.email,)
        )

        if cursor.fetchone():
            conn.close()
            raise HTTPException(
                status_code=409,
                detail="Email already exists."
            )

        password_hash = pwd_context.hash(request.password)

        cursor.execute("""
            INSERT INTO security_users
            (full_name, employee_id, email, password_hash, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            request.full_name,
            request.employee_id,
            request.email,
            password_hash,
            request.role,
            datetime.now().isoformat()
        ))

        conn.commit()
        conn.close()

        return {
            "message": "Account created successfully.",
            "full_name": request.full_name,
            "employee_id": request.employee_id,
            "email": request.email,
            "role": request.role
        }

    except HTTPException:
        raise

    except Exception as e:
        logger.error(f"Signup failed | error={str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Signup failed: {str(e)}"
        )


@app.post("/auth/login")
def login(request: LoginRequest):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT full_name, employee_id, email, password_hash, role
            FROM security_users
            WHERE employee_id = ?
        """, (request.employee_id,))

        user = cursor.fetchone()
        conn.close()

        if not user:
            raise HTTPException(
                status_code=404,
                detail="Account not found."
            )

        full_name, employee_id, email, password_hash, role = user

        if not pwd_context.verify(request.password, password_hash):
            raise HTTPException(
                status_code=401,
                detail="Incorrect password."
            )

        if role != "Security Analyst":
            raise HTTPException(
                status_code=403,
                detail="Only Security Analyst can access this app."
            )

        return {
            "message": "Login successful.",
            "full_name": full_name,
            "employee_id": employee_id,
            "email": email,
            "role": role
        }

    except HTTPException:
        raise

    except Exception as e:
        logger.error(f"Login failed | error={str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Login failed: {str(e)}"
        )


@app.post("/predict")
def predict(request: QueryRequest):
    try:
        print("Received request:", request.model_dump())

        payload = {
            "ai_query": request.ai_query,
            "action": request.action,
            "fortismb_role": request.fortismb_role,
            "file_op": request.file_op,
            "is_usb": request.is_usb,
            "hour": request.hour,
            "off_hours": request.off_hours,
            "date": request.date,
        }

        stage1_result = m1_service.predict(payload)

        final_result = {
            "ai_query": request.ai_query,
            "date": request.date,
            "stage1": stage1_result,
        }

        if stage1_result["label"] == "Elevated":
            stage2_result = m2_service.predict(payload)
            final_result["stage2"] = stage2_result

            if stage2_result["label"] == "High":
                final_result["final_risk"] = "High"
                final_result["system_action"] = "Block & Mitigate"
            else:
                final_result["final_risk"] = "Medium"
                final_result["system_action"] = "Alert & Verify"

        else:
            final_result["stage2"] = None
            final_result["final_risk"] = "Low"
            final_result["system_action"] = "Log & Monitor"

        final_result["ai_explanation"] = llm_service.explain_risk(
            payload,
            final_result
        )

        logger.info(f"200 Success | input={request.model_dump()}")

        return final_result

    except HTTPException as e:
        logger.error(
            f"HTTP Error | detail={e.detail} | input={request.model_dump()}"
        )
        raise e

    except Exception as e:
        error_trace = traceback.format_exc()

        logger.error(
            f"500 Internal Error | input={request.model_dump()} | error={str(e)}\n{error_trace}"
        )

        raise HTTPException(
            status_code=500,
            detail="Internal server error. Check logs."
        )