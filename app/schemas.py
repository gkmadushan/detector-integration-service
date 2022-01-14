from datetime import time
from pydantic import BaseModel, Field
from typing import List, Optional


class OVALScanRequest(BaseModel):
    ipv4: Optional[str]
    ipv6: Optional[str]
    username: str
    port: int
    os: str
    secret_id: Optional[str]
    reference: Optional[str]
    autofix: bool = False
    notify_to: Optional[List[str]]
    target_name: str
    target_url: str
    created_by: Optional[str] = None
