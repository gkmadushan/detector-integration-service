from sqlalchemy.sql.expression import false
from sqlalchemy.sql.sqltypes import DateTime
from sqlalchemy.exc import IntegrityError
from starlette.responses import Response
from fastapi import APIRouter, Depends, HTTPException, Request
from dependencies import common_params, get_db, get_secret_random, process_oval_results
from sqlalchemy.orm import Session
from typing import Optional
from dependencies import get_token_header
import uuid
from datetime import datetime
from exceptions import username_already_exists
from sqlalchemy import over
from sqlalchemy import engine_from_config, and_, func, literal_column, case
from sqlalchemy_filters import apply_pagination
import time
import os
import uuid
from sqlalchemy.dialects import postgresql
import xml.etree.ElementTree as ET
# import xmltodict
import json
import subprocess
from schemas import OVALScanRequest



page_size = os.getenv('PAGE_SIZE')

router = APIRouter(
    prefix="/v1/scans",
    tags=["DetectorServiceAPIs"],
    # dependencies=[Depends(get_token_header)],
    responses={404: {"description": "Not found"}},
)


@router.post("")
def oval_scan(details: OVALScanRequest):
    scan_types = {'oval': 'oval eval', 'xccdf':'xccdf eval'}
    scan_type = scan_types.get(details.scan_type, 'oval eval')
    username = details.username
    if details.ipv6:
        host = details.ipv6
    else:
        host = details.ipv4
    port = details.port

    scanners = {'openscap': 'oscap-ssh'}
    scanner = scanners.get(details.scanner, 'oscap-ssh')

    result_file = uuid.uuid4()
    process = subprocess.Popen(f"{scanner} {username}@{host} {port} {scan_type} --results results/{result_file}.xml datasets/com.ubuntu.xenial.usn.oval.xml", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    
    console_log = ''
    for line in process.stdout.readlines():
        console_log += line.decode("utf-8", "ignore").replace('\n','').replace('\r\n','').replace('\r','')

    retval = process.wait()
    if(retval == 0):
        return process_oval_results(f"results/{result_file}.xml")
    else:
        raise HTTPException(status_code=422, detail=console_log)
    # return process_oval_results("results/0e117d4d-efc2-4167-ab45-23cf8a894055.xml")

