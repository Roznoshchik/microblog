from flask import jsonify
import json
import requests
from app import app
import uuid

def translate(text, source_language, dest_language):
    if 'MS_TRANSLATOR_KEY' not in app.config or \
            not app.config['MS_TRANSLATOR_KEY']:
        return 'ERROR: the translation service is not configured.'

    auth = {
        'Ocp-Apim-Subscription-Key': app.config['MS_TRANSLATOR_KEY'], 
        'Ocp-Apim-Subscription-Region': 'westeurope',
        'Content-type': 'application/json',
        'X-ClientTraceId': str(uuid.uuid4())
    }

    payload = {'from': source_language, 'to':dest_language}
    data = [{'text': text}]
    
    r = requests.post('https://api.cognitive.microsofttranslator.com/translate?api-version=3.0&from={}&to={}'.format(source_language, dest_language), headers=auth, json=data)
    
 
    if r.status_code != 200:
        return ['Error: the translation service failed.', r]
    r=r.json()
   
    return r
    #return json.loads(r.content.decode('utf-8-sig'))




