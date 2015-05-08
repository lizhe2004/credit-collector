'''
Created on Dec 4, 2012

@author: lizhe2004
'''
from urllib2 import Request
from random import randint
from urllib import urlencode
import urllib2
import cookielib
import traceback
import getpass

class PointManager:
    def __init__(self,user,password):
        self.user = user
        self.password = password
        self.cj = cookielib.LWPCookieJar()
        self.opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(self.cj))
        urllib2.install_opener(self.opener)   
    def login(self):
        #the login button height 26 weight 86
        button_x = randint(5,80)# m 86
        button_y = randint(5,20) #26
        
        postd_data= {"email":self.user,"passwd":self.password,\
                     "reback":"http://www.51cto.com","button.x":str(button_x),"button.y":str(button_y)}
        
        data = urlencode(postd_data) 
        header={"User-Agent": "Mozilla-Firefox5.0","Connection":"keep-alive"}
        
        refer_page = "http://home.51cto.com/index.php?s=/Index/index/reback/http://www.51cto.com/"

        
        req = Request("http://home.51cto.com/index.php?s=/Index/doLogin",data,header)
        content=urllib2.urlopen(req)
        respond= content.read()
        print respond
        import re
        pattern = re.compile(r'<script type="text/javascript"  src="') 
        match = pattern.split(respond) 
           
        print match
        for i in range( 1,len(match)):  
            url= match[i]
            right = url.find("\"></script>")
            url= url[:right]
            try:
                content=urllib2.urlopen(url)
                print content.read()  
            except:
                traceback.print_exc()
 
               
  
    
    def getMsg(self,id):
 
        postd_data= {"uid":str(id)}#6242311
        data = urlencode(postd_data) 
        header={"User-Agent": "Mozilla-Firefox5.0","Connection":"keep-alive"}
        
        refer_page = "http://home.51cto.com/index.php?s=/Home/index"

        req = Request("http://home.51cto.com/index.php?s=/Index/getMsgCount",data,header)
        content=urllib2.urlopen(req)
        print id
        print content.read()    
        
  
    
    def logout(self):
 
        url = "http://home.51cto.com/index.php?s=/Index/logout/reback/http://www.51cto.com/"
        content=urllib2.urlopen(url)
        respond= content.read()
         
        #import re
        #pattern = re.compile(r'<script type="text/javascript" src="') 
        
        #match = pattern.split(respond) 
          
        #print match
        #for i in range( 1,len(match)):
          
            #url= match[i]
            #right = url.find("\"></script>")
            #url= url[:right]
            #content=urllib2.urlopen(url)
            #print content.read()   
 
        
    def getStatus(self):
        
        url = "http://home.51cto.com/index.php?s=/Index/getLoginStatus/"
        content=urllib2.urlopen(url)
        respond= content.read()
        print respond
    def getfreecredits(self):
        
        header={"User-Agent": "Mozilla-Firefox5.0","Connection":"keep-alive"}
        req = Request("http://down.51cto.com/download.php?do=getfreecredits&t=0.703364356720097","",header)
        content=urllib2.urlopen(req)
        respond= content.read()
        print respond
        

user = raw_input('user: ')
password = getpass.getpass('password: ')        
pm = PointManager(user,password) 
pm.login()
pm.getfreecredits()
pm.logout()
pm.getfreecredits()
pm.getMsg("4714272")
 
        