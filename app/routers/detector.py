from sqlalchemy.sql.expression import false
from sqlalchemy.sql.sqltypes import DateTime
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
from sqlalchemy import over, text
from sqlalchemy import engine_from_config, and_, func, literal_column, case
from sqlalchemy_filters import apply_pagination
import time
import os
import uuid
import json
import subprocess
from schemas import OVALScanRequest
from models import ScanType, Dataset, Profile, Scan, Result, Reference, ScanStatu, Clas, O
import requests
import pika  # rabbitmq
from matplotlib import colors
import matplotlib.pyplot as plt
import base64
import io
import sys


page_size = os.getenv('PAGE_SIZE')
CREDENTIAL_SERVICE_URL = os.getenv('CREDENTIAL_SERVICE_URL')
RABBITMQ_HOST = os.getenv('RABBITMQ_HOST')

router = APIRouter(
    prefix="/v1/scans",
    tags=["DetectorServiceAPIs"],
    # dependencies=[Depends(get_token_header)],
    responses={404: {"description": "Not found"}},
)


@router.post("")
def scan(details: OVALScanRequest, db: Session = Depends(get_db)):
    scan_type_query = db.query(ScanType)
    if scan_type_query.count() > 0:
        id = uuid.uuid4().hex
        # Store scan request
        scan_status = db.query(ScanStatu).filter(ScanStatu.code == "SCANNING").one()
        scan = Scan(
            id=id,
            started_at=datetime.now(),
            scan_status_id=scan_status.id,
            reference=details.reference
        )

        try:
            db.add(scan)
            db.commit()
        except IntegrityError as err:
            db.rollback()

        for scan_type in scan_type_query.all():
            # list of available commands based on the scan type
            scan_type_commands = {'OVAL': 'oval eval', 'XCCDF': 'xccdf eval'}
            scan_command = scan_type_commands.get(scan_type.code, '')

            # get the dataset based on the OS and scan type
            dataset_query = db.query(Dataset).filter(Dataset.scan_type == scan_type, Dataset.os == details.os)
            if dataset_query.count() > 0:
                dataset = dataset_query.first()
            else:
                # raise HTTPException(status_code=422, detail="Invalid OS or dataset not found")
                continue

            # result types
            result_types = {'OVAL': '--results', 'XCCDF': '--results-arf'}
            result_type = result_types.get(scan_type.code, '--results')

            if details.ipv6:
                host = details.ipv6
            else:
                host = details.ipv4

            port = details.port
            username = details.username

            profile_command = ''

            if scan_type.code == 'XCCDF':
                profile_query = db.query(Profile).filter(Profile.dataset == dataset)
                if profile_query.count() > 0:
                    profile = profile_query.first()
                    profile_command = f'--profile {profile.code}'
                    if details.autofix == True:
                        profile_command = profile_command + ' --remediate'
                else:
                    # raise HTTPException(status_code=422, detail="Invalid Profile")
                    continue

            result_file = uuid.uuid4()

            # retrive keys
            response = requests.get(CREDENTIAL_SERVICE_URL+'/v1/credentials/'+details.secret_id)
            try:
                response_json = json.loads(response.text)
            except:
                return response.text
            encrypted_key = response_json['data']['encrypted_key']
            key_file_path = "keys/"+str(id)+str(result_file)+".ppk"
            key_file = open(key_file_path, "w")
            key_file.write(encrypted_key)
            key_file.close()
            os.chmod(key_file_path, int('600', base=8))

            process = subprocess.Popen(
                f"export SSH_ADDITIONAL_OPTIONS='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i {key_file_path}' && oscap-ssh {username}@{host} {port} {scan_command} {profile_command} {result_type} results/{result_file}.xml datasets/{dataset.file}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

            console_log = ''
            for line in process.stdout.readlines():
                console_log += line.decode("utf-8", "ignore").replace('\n', '').replace('\r\n', '').replace('\r', '')

            return console_log

            # delete key file
            os.remove(key_file_path)

            return f"results/{result_file}.xml"

            if os.path.exists(f"results/{result_file}.xml"):
                # Scan completed
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
                    connection = pika.BlockingConnection(pika.ConnectionParameters(
                        RABBITMQ_HOST, heartbeat=300, blocked_connection_timeout=60))
                    channel = connection.channel()
                    all_classes = db.query(Clas).all()
                    for detection_classes in all_classes:
                        channel.queue_declare(queue=detection_classes.name, durable=True)

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
                            impact=res['impact'],
                            reference=details.reference
                        )
                        db.add(result)

                        if(len(res['references'])):
                            for reference in res['references']:
                                reference_entity = Reference(
                                    id=uuid.uuid4().hex,
                                    result_id=result_id,
                                    type_code=reference['type'],
                                    code=reference['ref'],
                                    name=reference['ref'],
                                    url=reference['URL']
                                )
                                db.add(reference_entity)

                        # push results to the queue
                        res['scan_id'] = id
                        res['reference'] = details.reference
                        channel.basic_publish(exchange='', routing_key=res['class'], body=json.dumps(res))

                    db.commit()
                    channel.queue_declare(queue='notifications', durable=True)
                    notification = scan_details_notify(details)
                    channel.basic_publish(exchange='', routing_key='notifications', body=json.dumps(notification))
                    connection.close()
                except IntegrityError as err:
                    db.rollback()

            else:
                scan_status = db.query(ScanStatu).filter(ScanStatu.code == "INTERRUPTED").one()
                scan.scan_status_id = scan_status.id
                try:
                    db.add(scan)
                    db.commit()
                except IntegrityError as err:
                    db.rollback()
                # raise HTTPException(status_code=422, detail=console_log)
                continue
    else:
        raise HTTPException(status_code=422, detail='No scan types')

    db.close()
    return True


@router.get("/types")
def get_by_filter(db: Session = Depends(get_db)):
    types = db.query(ScanType).all()

    response = {
        "data": types
    }

    return response


@router.get("/classes")
def get_by_filter(db: Session = Depends(get_db)):
    types = db.query(Clas).all()

    response = {
        "data": types
    }

    return response


@router.get("/os")
def get_by_filter(db: Session = Depends(get_db)):
    os = db.query(O).all()

    response = {
        "data": os
    }

    return response


@router.get("/graphs")
def new_issues(commons: dict = Depends(common_params), db: Session = Depends(get_db)):
    output = []
    # Issue summary graph
    result = db.execute(text(f"""
        select count(*), ss.name from scan s 
        inner join scan_status ss on ss.id = s.scan_status_id 
         group by ss.id, ss.name 
        """))
    rows = []
    db.close()
    try:
        for row in result:
            rows.append(row)

        y, x = zip(*rows)
        fig, ax = plt.subplots(figsize=(11, 4))
        f1 = io.BytesIO()

        plt.pie(y, labels=x)
        plt.title('Scan Summary for the last 7 Days')

        fig.savefig(f1, format="svg")

        output.append(base64.b64encode(f1.getvalue()))

        return output
    except:
        return []


@router.get("")
def get_by_filter(db: Session = Depends(get_db), resources: Optional[str] = None, page: Optional[str] = 1, limit: Optional[int] = page_size):
    filters = []

    if(resources):
        filters.append(Scan.reference.in_(resources.split(",")))
    else:
        filters.append(Scan.reference.ilike('%'))

    query = db.query(
        over(func.row_number(), order_by='started_at').label('index'),
        Scan.id,
        Scan.started_at,
        Scan.ended_at,
        ScanStatu.name,
        Scan.reference
    )

    query, pagination = apply_pagination(query.where(
        and_(*filters)).join(Scan.scan_status).order_by(Scan.started_at.asc()), page_number=int(page), page_size=int(limit))

    response = {
        "data": query.all(),
        "meta": {
            "total_records": pagination.total_results,
            "limit": pagination.page_size,
            "num_pages": pagination.num_pages,
            "current_page": pagination.page_number
        }
    }

    return response


@router.get("/{id}")
def get_by_id(id: str, db: Session = Depends(get_db)):
    filters = []

    if(id):
        filters.append(Result.scan_id == id)

    query = db.query(
        Result.id,
        Clas.name,
        Result.title,
        Result.description,
        Result.status,
        Result.score,
        Result.fix_available,
        Result.impact,
        Result.reference
    )
    results = query.where(
        and_(*filters)).join(Result._class).all()
    if results == None:
        raise HTTPException(status_code=404, detail="Scan results not found")
    response = {
        "data": results
    }
    return response
