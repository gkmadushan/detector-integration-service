from datetime import time
from pydantic import BaseModel, Field
from typing import List, Optional

class OVALScanRequest(BaseModel):
    scan_type: str
    ipv4: Optional[str]
    ipv6: Optional[str]
    username: str
    port: int
    os: str
    profile: Optional[str]
    secret_id: Optional[str]
    reference: Optional[str]