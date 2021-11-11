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

async def get_token_header(access_token: Optional[str] = Cookie(default=None), request: Request = None):
    user_id = validate_token(access_token)
    if user_id == False:
        raise HTTPException(status_code=401, detail="Authorization Bearer token invalid or expired")
    else:
        return user_id

def hash(plaintext: str):
    return hashlib.sha512(str(plaintext+os.getenv('HASH_SALT')).encode('utf-8')).hexdigest()

def generate_token(user_id,  lifetime = 5):
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

def refresh_token(refresh_token,  lifetime = 5):
    user_id = validate_token(refresh_token)
    if(user_id !=False):
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
        'ns0':'http://oval.mitre.org/XMLSchema/oval-results-5', 
        'ns2':'http://oval.mitre.org/XMLSchema/oval-common-5',
        'ns3':'http://oval.mitre.org/XMLSchema/oval-definitions-5'
    }

    issues = []

    for result in root.findall('./ns0:results/ns0:system/ns0:definitions/ns0:definition', namespaces=namespaces):
        # print(result.attrib)
        # print(result.attrib['definition_id'])
        if(result.attrib['result'] == 'true'):
            id = result.attrib['definition_id']
            definition = root.find(f"./ns3:oval_definitions/ns3:definitions/ns3:definition[@id='{id}']", namespaces=namespaces)
            title = definition.find('./ns3:metadata/ns3:title', namespaces=namespaces)
            description = definition.find('./ns3:metadata/ns3:description', namespaces=namespaces)
            references = definition.findall('./ns3:metadata/ns3:reference', namespaces=namespaces)

            refs = []
            for reference in references:
                print(reference.attrib)
                refs.append({'type':reference.attrib['source'], 'ref':reference.attrib['ref_id'], 'URL':reference.attrib['ref_url']})
            
            issues.append({
                'title': title != None and title.text or id,
                'description': description != None and description.text or "" ,
                'class': definition.attrib['class'],
                'references': refs,
            })
        
    return issues