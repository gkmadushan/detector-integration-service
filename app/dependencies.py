from uuid import uuid4
from fastapi import Header, HTTPException, Depends, status, Cookie, Request
from utils.database import get_db
from utils.email import send_email
import hashlib
import os
import jwt
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer
import secrets
import string
from typing import Optional
import xml.etree.ElementTree as ET


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
alphabet = string.ascii_letters + string.digits
BASE_URL = os.getenv('BASE_URL')


async def get_token_header(access_token: Optional[str] = Cookie(default=None), request: Request = None):
    user_id = validate_token(access_token)
    if user_id == False:
        raise HTTPException(status_code=401, detail="Authorization Bearer token invalid or expired")
    else:
        return user_id


def hash(plaintext: str):
    return hashlib.sha512(str(plaintext+os.getenv('HASH_SALT')).encode('utf-8')).hexdigest()


def generate_token(user_id,  lifetime=5):
    payload = {
        'exp': datetime.utcnow() + timedelta(days=0, minutes=lifetime),
        'iat': datetime.utcnow(),
        'sub': user_id
    }
    return jwt.encode(
        payload,
        os.getenv('JWT_SECRET'),
        algorithm='HS256'
    )


def refresh_token(refresh_token,  lifetime=5):
    user_id = validate_token(refresh_token)
    if(user_id != False):
        return generate_token(user_id)
    else:
        return False


def validate_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, os.getenv('JWT_SECRET'), algorithms=['HS256'])
        user_id: str = payload.get("sub")
    except:
        return False

    return user_id


def get_secret_random(size=100):
    return ''.join(secrets.choice(alphabet) for i in range(size))


async def common_params():
    return {}


async def send_email_handler():
    send_email()


def process_oval_results(result_file):
    xml = ET.parse(result_file)
    root = xml.getroot()
    # below code will output the xml into a file with namespace mapping
    # f = open('out.xml', 'w')
    # f.write(ET.tostring(root, encoding='utf8').decode('utf8'))
    namespaces = {
        'ns0': 'http://oval.mitre.org/XMLSchema/oval-results-5',
        'ns2': 'http://oval.mitre.org/XMLSchema/oval-common-5',
        'ns3': 'http://oval.mitre.org/XMLSchema/oval-definitions-5'
    }

    issues = []

    for result in root.findall('./ns0:results/ns0:system/ns0:definitions/ns0:definition', namespaces=namespaces):
        if(result.attrib['result'] == 'true' or result.attrib['result'] == 'false'):
            id = result.attrib['definition_id']
            vulnerable = result.attrib['result'] == 'true' and True or False
            definition = root.find(
                f"./ns3:oval_definitions/ns3:definitions/ns3:definition[@id='{id}']", namespaces=namespaces)
            title = definition.find('./ns3:metadata/ns3:title', namespaces=namespaces)
            description = definition.find('./ns3:metadata/ns3:description', namespaces=namespaces)
            references = definition.findall('./ns3:metadata/ns3:reference', namespaces=namespaces)
            serverity_elem = definition.find('./ns3:metadata/ns3:advisory/ns3:severity', namespaces=namespaces)
            issued_date_elem = definition.find('./ns3:metadata/ns3:advisory/ns3:issued', namespaces=namespaces)

            try:
                issued_date = issued_date_elem.attrib['date']
            except:
                issued_date = ''
            try:
                serverity = serverity_elem.text
            except:
                serverity = 'low'

            refs = [{'type': 'OVAL', 'ref': id, 'URL': None}]
            for reference in references:
                refs.append({'type': reference.attrib['source'],
                            'ref': reference.attrib['ref_id'], 'URL': reference.attrib['ref_url']})
            issues.append({
                'title': title != None and title.text or id,
                'description': description != None and description.text or "",
                'class': definition.attrib['class'],
                'status': vulnerable,
                'references': refs,
                'severity': serverity,
                'issued_date': issued_date,
                'fixes': [],
                'impact': ""
            })

    return issues


def process_xccdf_results(result_file):
    xml = ET.parse(result_file)
    root = xml.getroot()
    namespaces = {
        'ns0': 'http://scap.nist.gov/schema/asset-reporting-format/1.1',
        'ns12': 'http://checklists.nist.gov/xccdf/1.2',
        'ns2': 'http://scap.nist.gov/schema/scap/source/1.2'
    }

    issues = []

    for result in root.findall('./ns0:reports/ns0:report/ns0:content/ns12:TestResult/ns12:rule-result', namespaces=namespaces):

        status = result.find('./ns12:result', namespaces=namespaces)
        status_options = {'pass': True, 'fail': False, 'error': False}
        if status_options.get(status.text) != None:
            id = result.attrib['idref']
            definition = root.find(f".//ns12:Rule[@id='{id}']", namespaces=namespaces)
            title = definition.find('.//ns12:title', namespaces=namespaces)
            description = definition.find('.//ns12:description', namespaces=namespaces)
            severity = definition.attrib['severity']
            refs = []
            for reference in definition.findall('.//ns12:reference', namespaces=namespaces):
                refs.append({'type': 'default', 'ref': reference.text, 'URL': reference.attrib['href']})

            fixes = []
            for fix in definition.findall('.//ns12:fix', namespaces=namespaces):
                fixes.append({'system': fix.attrib['system'], 'script': fix.text})

            impact = definition.find('.//rationale', namespaces=namespaces)

            issues.append({
                'title': title != None and title.text or id,
                'description': description != None and description.text or "",
                'class': 'compliance',
                'status': status_options.get(status.text),
                'severity': severity,
                'issued_date': '',
                'references': refs,
                'fixes': fixes,
                'impact': impact != None and impact.text or ""
            })

    return issues


def scan_details_notify(scan_details):
    notification = {
        'to': scan_details.notify_to,
        'subject': 'Vulnerabilities detected in resource '+scan_details.target_name,
        'message': 'Hi</br><br/>Automated Vulnerability Management System identified several issues in the '+scan_details.target_name+'<br/><br/>Please login to the portal to act on the outstanding tasks<br/><a href="'+BASE_URL+'">Login</a><br/><br/>Thank you<br/>SecOps - Automated Vulnerability Management System',
    }
    return notification
