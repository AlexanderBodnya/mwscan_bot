import os
from flask import Flask, request
import telepot
from telepot.loop import OrderedWebhook
from telepot.delegate import (
    per_chat_id_in,
    per_application,
    call,
    create_open,
    pave_event_space
    )
import requests
import time
import os
import threading
import queue

VT_API_KEY = 'your VT_API_KEY'

class VirusTotalFileScan():
    
    def __init__(self, VT_API_KEY):
        self.VT_API_KEY = VT_API_KEY
        
    def vt_scan_request(self, VT_API_KEY, filename):
        params = {'apikey':VT_API_KEY}
        files = {
            'file': (filename, open(filename, 'rb'))
        }
        response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, data=params)
        return response
        
    def vt_scan_response(self, VT_API_KEY, scan_id):
        headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent" : "gzip, VT_test"
        }
        params = {
            'apikey': VT_API_KEY,
            'resource':scan_id,
        }
        response = requests.post('https://www.virustotal.com/vtapi/v2/file/report',
            params=params, 
            headers=headers)
        return response
            
    def scan_procedure(self, filename):
        while True:
            if self.vt_scan_request(self.VT_API_KEY, filename).status_code == 200:
                try:
                    json_response = self.vt_scan_request(self.VT_API_KEY, filename).json()
                    if json_response['response_code'] == 0:
                        break
                    elif json_response['response_code'] == 1:
                        break
                    else:
                        continue
                except:
                    continue
        scan_id = json_response['scan_id']
        
        while True:
             time.sleep(10)
             if self.vt_scan_response(self.VT_API_KEY, scan_id).status_code == 200: 
                try:
                    response = self.vt_scan_response(self.VT_API_KEY, scan_id)
                    json_response = response.json()
                    if json_response['response_code'] == 1:
                        break
                    else:
                        continue
                except:
                    continue
        return json_response



class ThreadingWrapper(threading.Thread):
    def start(self):
        super(ThreadingWrapper, self).start()
    
def threading_wrapper(func):
    def f(seed_tuple):
        target = func(seed_tuple)
            
        if type (target) is tuple:
            run, args,kwargs = target
            t = ThreadingWrapper(target = run, args = args, kwargs = kwargs)
        else:
            t = ThreadingWrapper(target = target)
            
        return t
    return f


class ChatBox(telepot.DelegatorBot):
    def __init__(self, token, queue):
        self._seen = set()
        self._queue = queue
        super(ChatBox, self).__init__(
            token,[
           
                (
                    self._is_newcomer,
                    threading_wrapper(call(self.on_chat_message))
                )
                
            ]
        )
        
    def _is_newcomer(self,msg):
        if telepot.is_event(msg):
            return None
        
        chat_id = msg['chat']['id']
        
        if chat_id in self._seen:
            return []
            
        self._seen.add(chat_id)
        return []
        
    def on_chat_message(self, seed_tuple):
        content_type, chat_type, chat_id = telepot.glance(seed_tuple[1])
        if content_type == 'text':    
            BOT.sendMessage(chat_id, 'I\'m bot which scans files for malware, please send me file and I will scan it. File size should not exceed 20 mb. Also - please avoid special symbols in names')
        elif content_type == 'document':
            file_id = seed_tuple[1]['document']['file_id']
            print(BOT.getFile(file_id))
            file = BOT.getFile(file_id)
            BOT.sendMessage(chat_id,"I will try to scan this file, using the Virus Total service. This may take a few minutes, due to Virus Total public API limitations. File name is "+str(file['file_path'])[10:])
            response = requests.get("https://api.telegram.org/file/bot"+TOKEN+'/'+file['file_path'], stream=True)
            # Throw an error for bad status codes
            response.raise_for_status()
            with open(file['file_id'], 'wb') as handle:
                for block in response.iter_content(1024):
                    handle.write(block)
            filescan = VirusTotalFileScan(VT_API_KEY)
            results = filescan.scan_procedure(file['file_id'])
            if results['positives'] == 0:
                BOT.sendMessage(chat_id, "Your file " + str(file['file_path'])[10:] + " is clean!")
            else:
                BOT.sendMessage(chat_id, "Your file"+str(file['file_path'])[10:]+" was detected by "+ str(results['positives'])+" of "+str(results['total'])+" vendors. More verbose information you can find following this link - "+results['permalink'] )
            os.remove(file['file_id'])
        
app = Flask(__name__)

os.environ['PP_BOT_TOKEN'] = 'TOKEN' # put your token in heroku app as environment variable
TOKEN = os.environ['PP_BOT_TOKEN']

SECRET = '/bot' + TOKEN
URL = 'URL' #  paste the url of your application

inbound_queue = queue.Queue()
outbound_queue = queue.Queue()

BOT = ChatBox(TOKEN, inbound_queue)

webhook = OrderedWebhook(BOT)

@app.route(SECRET, methods=['GET', 'POST'])
def pass_update():
    webhook.feed(request.data)
    return 'OK'

try:
    BOT.setWebhook(URL + SECRET)
except telepot.exception.TooManyRequestsError:
    pass

webhook.run_as_thread()

