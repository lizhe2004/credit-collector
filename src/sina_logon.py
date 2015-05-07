#ending=utf-8

'''
Created on Dec 6, 2012

@author: lizhe2004
'''

import sys
print sys.getdefaultencoding()
import rsa
import re 
import json
import urllib
import base64
import hashlib
from urllib2 import Request
from random import randint
from urllib import urlencode
import urllib2
import datetime
from lzRSA import RSAKey

WBCLIENT = 'ssologin.js(v1.4.2)'
sha1 = lambda x: hashlib.sha1(x).hexdigest()
import cookielib


def wblogin(username, password):
 
 
 
    a= RSAKey()
    e="10001"

 
 

    oldtime =datetime.datetime.strptime("1970-01-01","%Y-%m-%d")
    cj = cookielib.LWPCookieJar()
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
    urllib2.install_opener(opener)  
    
    headers={
        'Accept':"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        'Connection':"keep-alive",
        #'Accept-Language':'en-us,en;q=0.5',
        #'Accept-Encoding': 'gzip, deflate',
        'Host':"login.sina.com.cn",
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:10.0.11) Gecko/20100101 Firefox/10.0.11',
        "Referer":"http://www.weibo.com/",
    }
    content = urllib2.urlopen(\
                    "http://login.sina.com.cn/sso/prelogin.php?entry=sso&callback=sinaSSOController.preloginCallBack&su=dW5kZWZpbmVk&rsakt=mod&client=ssologin.js(v1.4.2)&_=1355809342296")
    
    responds = content.read()
     
    print responds
    pre_login_str = re.match(r'[^{]+({.+?})', responds).group(1)
    pre_login_json = json.loads(pre_login_str)
    pubkey = pre_login_json["pubkey"]
    
    
    a.RSASetPublic(pubkey,e)
     
    
    '''
    "retcode":0,
    "servertime":1355809346,
    "pcid":"hk-6da01ede8c00e479fd8527517198148e88ca"
    ,"nonce":"XTEYVD"
    ,"pubkey":"EB2A38568661887FA180BDDB5CABD5F21C7BFD59C090CB2D245A87AC253062882729293E5506350508E7F9AA3BB77F4333231490F915F6D63C55FE2F08A49B353F444AD3993CACC02DB784ABBB8E42A9B1BBFFFB38BE18D78E87A0E41B9B8F73A928EE0CCEE1F6739884B9777E4FE9E88A1BBE495927AC4A799B3181D6442443"
    ,"rsakv":"1330428213"
    ,"exectime":0
    '''
    
    print "\r\n"
    user = raw_input('user: ')
    password = getpass.getpass('password: ')   
    originalusername =user
    originalpassword = password
    urlencodedusername =urllib.quote(originalusername)
    print urlencodedusername
    print base64.b64encode(urlencodedusername)
    base64encodedusername = base64.b64encode(urlencodedusername)
    #base64encodedusername ="bGl6aGU1MjI4ODklNDBzaW5hLmNvbQ%3D%3D"#
 
    timenow = datetime.datetime.utcnow()
    print urlencode({"name": base64.b64encode(urlencodedusername)})
    
    
    microseconds = long((timenow - oldtime).total_seconds()*1000)
    callback= "STK_"+ str(microseconds)+"1"
    prelogin_start_time = datetime.datetime.utcnow()
    content=urllib2.urlopen(\
        'http://login.sina.com.cn/sso/prelogin.php?user=%s&checkpin=1&entry=sso&_t=1&callback=%s'\
        %(urlencodedusername,callback))
    responds = content.read()
    prelogin_end_time = datetime.datetime.utcnow()
    prelt = long((prelogin_end_time - prelogin_start_time).total_seconds()*1000)
    print responds
    pre_login_str = re.match(r'[^{]+({.+?})', responds).group(1)
    mach0= re.match(r'[^{]+({.+?})', responds).group(0)
    pre_login_json = json.loads(pre_login_str)
    
    
    rsaencodedpassword=""
    newst = long((datetime.datetime.utcnow()-oldtime).total_seconds())
    newst =  pre_login_json["servertime"]
    print newst
    password =str(newst)+"\t"+ pre_login_json['nonce']+"\n"+originalpassword
    print password
    rsaencodedpassword = a.RSAEncrypt(password) 
    print rsaencodedpassword
    data = {
        'entry': 'weibo',
        'gateway': 1,
        'from': '',
        'savestate': 7,
        'useticket': 1,
        'ssosimplelogin': 1,
        'su':base64encodedusername,
        'service': 'miniblog',
        'servertime': newst,
        'nonce': pre_login_json['nonce'],
        'vsnf': 1,
        "prelt":prelt,
        'pwencode': 'rsa2',
        "rsakv": "1330428213",
        'sp': rsaencodedpassword,
        'encoding': 'UTF-8',
        'url': 'http://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack',
        'returntype': 'META'
    }

    print urlencode(data)
    send = "entry=weibo&gateway=1&from=&savestate=7&useticket=1&vsnf=1&ssosimplelogin=1&su="+base64encodedusername+"&service=miniblog&servertime="+str(newst)+"&nonce="+str(pre_login_json['nonce'])+"&pwencode=rsa2&rsakv=1330428213&sp="+rsaencodedpassword+"&encoding=UTF-8&prelt="+str(prelt)+"&url=http%3A%2F%2Fwww.weibo.com%2Fajaxlogin.php%3Fframelogin%3D1%26callback%3Dparent.sinaSSOController.feedBackUrlCallBack&returntype=META"
     
    print send
    req = Request('http://login.sina.com.cn/sso/login.php?client=%s' % WBCLIENT, send,headers)
                    
    content=urllib2.urlopen(req)
    respond= content.read()
    print respond
    
    print type(respond) 
    weibo_url = re.search('(http://www\.weibo\.com.+)\'\)', respond).group(1)
    print weibo_url
     
    content = urllib2.urlopen(weibo_url)
    
    responds = content.read()
    print responds
     


if __name__ == '__main__':
    from pprint import pprint
    user = raw_input('user: ')
    password = getpass.getpass('password: ')   
    print(wblogin(user, password))
 
 