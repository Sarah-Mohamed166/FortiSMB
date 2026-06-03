import logging
import traceback
from typing import Optional, Literal


from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

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

## Allowed Roles
- Administrative Employee
- Administrative Manager
- Contractor
- System Administrator
- Executive

## Prediction Flow
- Stage 1: M1 predicts `Low` or `Elevated`
- Stage 2: M2 runs only if Stage 1 is `Elevated`
- LLM: Gemini generates a short explanation for the final result
"""
)

m1_service = M1()
m2_service = M2()
llm_service = LLMService()


class QueryRequest(BaseModel):
    ai_query: str = Field(
        ...,
        description="Natural-language AI query describing the event or what to analyze."
    )
    action: Literal["logon", "file", "device"] = Field(
        ...,
        description="Type of activity event."
    )
    fortismb_role: Literal[
        "Administrative Employee",
        "Administrative Manager",
        "Contractor",
        "System Administrator",
        "Executive"
    ] = Field(
        ...,
        description="FortiSMB role of the user."
    )
    file_op: Optional[str] = Field(
        default="",
        description="File operation such as read, write, copy, or delete."
    )
    is_usb: bool = Field(
        default=False,
        description="Whether USB/removable media was involved."
    )
    hour: float = Field(
        ...,
        ge=0,
        le=23,
        description="Event hour from 0 to 23."
    )
    off_hours: bool = Field(
        default=False,
        description="True if event happened outside approved working hours."
    )
    date: Optional[str] = Field(
        default=None,
        description="Optional event date, for example 2026-04-18."
    )


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
    return {"message": "FortiSMB FastAPI is running"}


@app.post("/predict")
def predict(request: QueryRequest):
    try:
         # 🔥 ADD THIS LINE HERE
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

        final_result["ai_explanation"] = llm_service.explain_risk(payload, final_result)

        logger.info(f"200 Success | input={request.model_dump()}")
        return final_result

    except HTTPException as e:
        logger.error(f"HTTP Error | detail={e.detail} | input={request.model_dump()}")
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