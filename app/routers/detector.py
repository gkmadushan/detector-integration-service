from sqlalchemy.sql.expression import false
from sqlalchemy.sql.sqltypes import DateTime
from sqlalchemy.exc import IntegrityError
from starlette.responses import Response
from fastapi import APIRouter, Depends, HTTPException, Request
from dependencies import common_params, get_db, get_secret_random, process_oval_results, process_xccdf_results
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
from models import ScanType, Dataset, Profile, Scan, Result, Reference, ScanStatu, Clas



page_size = os.getenv('PAGE_SIZE')

router = APIRouter(
    prefix="/v1/scans",
    tags=["DetectorServiceAPIs"],
    # dependencies=[Depends(get_token_header)],
    responses={404: {"description": "Not found"}},
)


@router.post("")
def scan(details: OVALScanRequest, db: Session = Depends(get_db)):

    scan_type_query = db.query(ScanType).filter(ScanType.code.ilike(details.scan_type.strip()))
    if(scan_type_query.count() > 0):
        scan_type = scan_type_query.one()
    else:
        raise HTTPException(status_code=422, detail="Invalid scan type") 

    #list of available commands based on the scan type
    scan_type_commands = {'OVAL': 'oval eval', 'XCCDF':'xccdf eval'}
    scan_command = scan_type_commands.get(scan_type.code, '')
    
    #get the dataset based on the OS and scan type
    dataset_query = db.query(Dataset).filter(Dataset.scan_type == scan_type, Dataset.os == details.os)
    if dataset_query.count() > 0:
        dataset = dataset_query.one()
    else:
        raise HTTPException(status_code=422, detail="Invalid OS") 

    #Store scan request
    scan_status = db.query(ScanStatu).filter(ScanStatu.code == "SCANNING").one()
    id = uuid.uuid4().hex
    scan = Scan(
        id = id,
        started_at = datetime.now(),
        scan_type_id = scan_type.id,
        scan_status_id = scan_status.id
    )

    try:
        db.add(scan)
        db.commit()
    except IntegrityError as err:
        db.rollback()

    #result types
    result_types = {'OVAL':'--results', 'XCCDF':'--results-arf'}
    result_type = result_types.get(scan_type.code, '--results')

    if details.ipv6:
        host = details.ipv6
    else:
        host = details.ipv4

    port = details.port
    username = details.username

    profile_command = ''

    if scan_type.code == 'XCCDF':
        profile_query = db.query(Profile).filter(Profile.dataset == dataset, Profile.id == details.profile)
        if profile_query.count() > 0:
            profile = profile_query.one()
            profile_command = f'--profile {profile.code}'
        else:
            raise HTTPException(status_code=422, detail="Invalid Profile")

    result_file = uuid.uuid4()
    process = subprocess.Popen(f"oscap-ssh {username}@{host} {port} {scan_command} {profile_command} {result_type} results/{result_file}.xml datasets/{dataset.file}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
   
    console_log = ''
    for line in process.stdout.readlines():
        console_log += line.decode("utf-8", "ignore").replace('\n','').replace('\r\n','').replace('\r','')


    if os.path.exists(f"results/{result_file}.xml"):
        #Scan completed
        scan_status = db.query(ScanStatu).filter(ScanStatu.code == "ENDED").one()
        scan.scan_status_id = scan_status.id
        scan.ended_at = datetime.now()
        try:
            db.add(scan)
            db.commit()
        except IntegrityError as err:
            db.rollback()

        if scan_type.code == 'OVAL':
            results = process_oval_results(f"results/{result_file}.xml")
        elif scan_type.code == 'XCCDF':
            results = process_xccdf_results(f"results/{result_file}.xml")

        try:
            for res in results:
                classdef = db.query(Clas).filter(Clas.code == res['class']).one()
                result_id = uuid.uuid4().hex
                result = Result(
                    id=result_id,
                    scan_id=id,
                    class_id=classdef.id,
                    title=res['title'],
                    description=res['description'],
                    status=res['status'] == True and True or False,
                    score=res['severity'],
                    fix_available=len(res['fixes']) > 0 and True or False,
                    impact=res['impact']
                )
                db.add(result)

                if(len(res['references'])):
                    for reference in res['references']:
                        reference_entity = Reference(
                            id=uuid.uuid4().hex,
                            result_id=result_id,
                            type_code = reference['type'],
                            code=reference['ref'],
                            name=reference['ref'],
                            url=reference['URL']
                        )
                        db.add(reference_entity)
                

            db.commit()
        except IntegrityError as err:
            db.rollback()
        return {}

    else:
        scan_status = db.query(ScanStatu).filter(ScanStatu.code == "INTERRUPTED").one()
        scan.scan_status_id = scan_status.id
        try:
            db.add(scan)
            db.commit()
        except IntegrityError as err:
            db.rollback()
        raise HTTPException(status_code=422, detail=console_log)

