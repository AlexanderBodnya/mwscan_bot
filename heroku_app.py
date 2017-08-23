import os
from flask import Flask, request
import telepot
from telepot.loop import OrderedWebhook
from telepot.delegate import call
import requests
import time
import os
import threading
import queue
import hashlib

HELP_MESSAGE = "Here's the list of available commands: \n /start - display welcome message \n /help - display this message \n /hash [md5/sha1/sha256] - check hash against Virus Total databases \n Send file to check it against VT databases"
WELCOME_MESSAGE = "Hello! I'm a bot, which scans files, using Virus Total API. You can use /help command to access help message or just send me a sample, which you want to check"
SCANFILE_MESSAGE = "I will try to scan this file, using the Virus Total service. This may take a few minutes, due to Virus Total public API limitations. File name is "

VT_API_KEY = 'Virus Total API Key'


print(threading.current_thread())

def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()
    
def downloader(response,filename):
    response.raise_for_status()
    with open(filename, 'wb') as handle:
        for block in response.iter_content(1024):
            handle.write(block)

class VirusTotalFileScan():
    
    def __init__(self, VT_API_KEY):
        self.VT_API_KEY = VT_API_KEY
        
    def vt_scan_request(self, VT_API_KEY, filename):
        params = {'apikey':VT_API_KEY}
        files = {
            'file': (filename, open(filename, 'rb'))
        }
        hash_file = md5(filename)
       
        while True:
            time.sleep(2)
            response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, data=params)
            if response.status_code ==200:
                json_response = response.json()
                if json_response['response_code'] == 0:
                    break
                elif json_response['response_code'] == 1:
                    break
        
        return (json_response,hash_file)
        
    def vt_scan_response(self, VT_API_KEY, resource):
        headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent" : "gzip, VT_test"
        }
        params = {
            'apikey': VT_API_KEY,
            'resource':resource,
        }
        
        while True:
            response = requests.post('https://www.virustotal.com/vtapi/v2/file/report',
            params=params, 
            headers=headers)
            time.sleep(10)
            if response.status_code ==200:
                json_response = response.json()
                print(json_response)
                if json_response['response_code'] == 0:
                    json_response = 0
                elif json_response['response_code'] == 1:
                    break
               
        return json_response

    def scan_procedure(self, filename):
        json_response, hash_file = self.vt_scan_request(self.VT_API_KEY, filename)
        json_response = self.vt_scan_response(self.VT_API_KEY, hash_file)

        return json_response
        
    def results_parser(self,json_response):
        if json_response['response_code'] == 1:
            positives = json_response['positives']
            total = json_response['total']
            permalink = json_response['permalink']
            
            return (positives, total, permalink)
        
        else:
            
            return json_response['response_code']
        



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
    def __init__(self, token):
        self._seen = set()
        self._queue = queue.Queue()
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
        
    def help_message(self, chat_id, *args):
         BOT.sendMessage(chat_id, str(HELP_MESSAGE))
         return 0
         
    def welcome_message(self, chat_id, *args):
         BOT.sendMessage(chat_id, str(WELCOME_MESSAGE))
         return 0
         
    def hash_command(self, chat_id, hash_value = None):
        if hash_value == None:
            BOT.sendMessage(chat_id,'Missing hash value!')
            return 0
        BOT.sendMessage(chat_id,'I will try to check this hash against Virus Total bases')
        filescan = VirusTotalFileScan(VT_API_KEY)
        results = filescan.vt_scan_response(filescan.VT_API_KEY,hash_value)
        print(results)
        parsed_results = filescan.results_parser(results)
        print(parsed_results)
        if type(results) != int:
            BOT.sendMessage(chat_id, "Your hash "+str(hash_value)+" was detected by "+ str(parsed_results[0])+" of "+str(parsed_results[1])+" vendors. More verbose information you can find following this link - "+parsed_results[2] )
        else:
            BOT.sendMessage(chat_id, "Error occured during hash retrieval, try again later") 
    
    commands_dict = {
        '/help' : help_message,
        '/start' : welcome_message,
        '/hash' : hash_command
    }
    
    def on_chat_message(self, seed_tuple):
        msg = seed_tuple[1]
        content_type, chat_type, chat_id = telepot.glance(msg)
        print(chat_id)

        if content_type =='document':
            file_id = msg['document']['file_id']
            file = BOT.getFile(file_id)
            BOT.sendMessage(chat_id,SCANFILE_MESSAGE+str(file['file_path'])[10:])
            response = requests.get("https://api.telegram.org/file/bot"+TOKEN+'/'+file['file_path'], stream=True)
            url = "https://api.telegram.org/file/bot"+TOKEN+'/'+file['file_path']
            self._queue.put(url, block = True)
            downloader(response,file['file_id'])
            filescan = VirusTotalFileScan(VT_API_KEY)
            results = filescan.scan_procedure(file['file_id'])
            parsed_results = filescan.results_parser(results)
            if type(parsed_results) != int:
                BOT.sendMessage(chat_id, "Your file "+str(file['file_path'])[10:]+" was detected by "+ str(parsed_results[0])+" of "+str(parsed_results[1])+" vendors. More verbose information you can find following this link - "+parsed_results[2])
            else:
                BOT.sendMessage(chat_id, "Error occured during data retrieval, try again later")
            os.remove(file['file_id'])
        elif content_type == 'text':
            text = msg['text']
            words = text.split()
            try:
                self.commands_dict[words[0]](self, chat_id, words[1])
            except:
                self.commands_dict[words[0]](self, chat_id)
        else:
            BOT.sendMessage(chat_id,"I don't understand")
    
   

        
app = Flask(__name__)

os.environ['PP_BOT_TOKEN'] = '' # put your token in heroku app as environment variable
TOKEN = os.environ['PP_BOT_TOKEN']

SECRET = '/bot' + TOKEN
URL = '' #  paste the url of your application



BOT = ChatBox(TOKEN)
bot = telepot.Bot(TOKEN)


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


    


