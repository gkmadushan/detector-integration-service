from datetime import time
from pydantic import BaseModel, Field
from typing import List, Optional

class CreateIssue(BaseModel):
    id: Optional[str]
    resource: str
    issue_status: str
    title: Optional[str]
    description: Optional[str]
    score: float
    issue_id: str
    remediation_script: str
    result_object: str

class OVALScanRequest(BaseModel):
    scan_type: str
    ipv4: Optional[str]
    ipv6: Optional[str]
    username: str
    port: int
    os: str
    scanner: Optional[str]