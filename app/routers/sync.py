import sys
import io
import base64
from sqlalchemy.sql.expression import false
from sqlalchemy.sql.sqltypes import Date, DateTime
from sqlalchemy.exc import IntegrityError
from starlette.responses import Response
from fastapi import APIRouter, Depends, HTTPException, Request
from dependencies import common_params, get_db, get_secret_random, process_oval_results, process_xccdf_results
from sqlalchemy.orm import Session
from typing import Optional
from dependencies import get_token_header, scan_details_notify
import uuid
from datetime import datetime
from exceptions import username_already_exists
from sqlalchemy import over, text, cast, func
from sqlalchemy import engine_from_config, and_, func, literal_column, case
from sqlalchemy_filters import apply_pagination
import time
import os
import uuid
import json
import subprocess
from schemas import OVALScanRequest
from models import ScanType, Dataset, Profile, Scan, Result, Reference, ScanStatu, Clas, O, Definition
import requests
import pika  # rabbitmq
from itertools import groupby

page_size = os.getenv('PAGE_SIZE')
CREDENTIAL_SERVICE_URL = os.getenv('CREDENTIAL_SERVICE_URL')
RABBITMQ_HOST = os.getenv('RABBITMQ_HOST')

router = APIRouter(
    prefix="/v1/sync",
    tags=["DetectorServiceSyncAPIs"],
    # dependencies=[Depends(get_token_header)],
    responses={404: {"description": "Not found"}},
)


@router.post("")
def scan(db: Session = Depends(get_db)):
    response = requests.get(
        'https://www.cvedetails.com/json-feed.php?numrows=30&vendor_id=0&product_id=0&version_id=0&hasexp=0&opec=0&opov=0&opcsrf=0&opfileinc=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&opginf=0&opdos=0&orderby=3&cvssscoremin=0')

    try:
        definitions = json.loads(response.text)
        c = 0
        for definition in definitions:
            cve = Definition(
                id=uuid.uuid4().hex,
                cve=definition['cve_id'],
                cwe=definition['cwe_id'],
                description=definition['summary'],
                score=definition['cvss_score'],
                exploit_count=definition['exploit_count'],
                publish_date=definition['publish_date'],
                url=definition['url']
            )

            try:
                c += 1
                db.add(cve)
                db.commit()
            except IntegrityError as err:
                c -= 1
                db.rollback()
        return c
    except:
        return False


@router.get("")
def get(score: Optional[str] = 4, db: Session = Depends(get_db)):
    filters = []
    filters.append(Definition.score >= score)

    query = db.query(
        Definition.id,
        func.Date(Definition.publish_date).label('publish_date'),
        Definition.cve,
        Definition.description,
        Definition.score,
        Definition.exploit_count,
        Definition.url
    )

    query, pagination = apply_pagination(query.where(
        and_(*filters)).order_by(Definition.publish_date.desc()), page_number=int(1), page_size=int(100))

    cve_dashboard = []
    for k, v in groupby(query.all(), key=lambda x: x['publish_date']):
        cve_list = list(v)
        info = {
            'publish_date': cve_list[0]['publish_date'],
            'list': cve_list
        }
        cve_dashboard.append(info)

    response = {
        "data": cve_dashboard,
        "meta": {
            "total_records": pagination.total_results,
            "limit": pagination.page_size,
            "num_pages": pagination.num_pages,
            "current_page": pagination.page_number
        }
    }

    return response
