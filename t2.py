#!/usr/bin/env python

import sys
import re
from flask import Flask
from flask import render_template
from flask import request
from flask import jsonify
import json
import os



sys.path.append("..")
sys.path.append(".")
import modsecurity


app = Flask(__name__)

@app.route('/')
def index():
    return 'Index Page'

req="""
GET /docs/index.html HTTP/1.1
Host: www.test101.com
Accept: image/gif, image/jpeg, */*
Accept-Language: en-us
Accept-Encoding: gzip, deflate
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)

"""
res="""
HTTP/1.1 200 OK
Date: Sun, 18 Oct 2009 08:56:53 GMT
Server: Apache/2.2.14 (Win32)
Last-Modified: Sat, 20 Nov 2004 07:16:26 GMT
ETag: "10000000565a5-2c-3e94b66c2e680"
Accept-Ranges: bytes
Content-Length: 44
Connection: close
Content-Type: text/html
X-Pad: avoid browser bug
  
<html><body><h1>It works!</h1></body></html>
"""

@app.route('/ruleTest', methods=['GET', 'POST'])
def ruleTest():
    srvalid="Valid"
    if request.method == 'POST':
        rule = request.form['rule']
        if rule:
            rules = modsecurity.Rules()
            ret = rules.load(str(rule))
            ret = rules.getParserError()
            if(ret == ""):
                valid = "Valid"
            else:
                valid = "Not Valid"
            res = {"R":ret, "X":valid}
            x = json.dumps(res, ensure_ascii=False).encode('utf8')
            return x
def parseRequest(req):
    method = ""
    uri = ""
    version = ""
    headerNames = []
    headerValues = []
    data =""
    x = req.split("\n")
    firstline = x[0].split(' ')
    if(len(firstline) < 3):
        return False
    else:
        method,uri,version = (firstline[0],firstline[1],firstline[2])
    if(len(x) > 1):
        for header in range(1,len(x)-1):
            if(x[header] == ""):
                continue
            headerNames.append((x[header][0:x[header].find(':')]).strip())
            headerValues.append((x[header][x[header].find(':')+1:]).strip())
        if(x[-2] == ""):
            data = x[-1]
    return (method,uri,version,headerNames,headerValues,data)             
    
@app.route('/runRequest', methods=['GET', 'POST'])
def runTest():
    srvalid="Valid"
    if request.method == 'POST':
        rule = request.form['rule']
        req = request.form['request']
        resp = request.form['response']
        if rule and (req or resp):
            print rule
            rule = "SecDebugLog /tmp/debug.log\nSecDebugLogLevel 4\n"+str(rule)
            modsec = modsecurity.msc_init()
            modsec.setConnectorInformation("ModSecurity- v0.0.1-alpha") 
            rules = modsecurity.Rules()

            ret = rules.load(str(rule))
            ret = rules.getParserError()
            if(ret != ""): 
                res = {"R":"Error we were unable to run your rules", "X":""}
                x = json.dumps(res, ensure_ascii=False).encode('utf8')
                return x
            assay = modsecurity.Assay(modsec,rules,None)
            method,uri,version,headerNames,headerValues,data = parseRequest(req)
            assay.processURI(str(uri),str(method),str(version))
            for i in range(0,len(headerNames)):
                assay.addRequestHeader(str(headerNames[i]),str(headerValues[i]))
            if(len(data) != 0):
                assay.appendRequestBody(str(data),len(data))
            method,uri,version,headerNames,headerValues,data = parseRequest(resp)
            for i in range(0,len(headerNames)):
                assay.addResponseHeader(str(headerNames[i]),str(headerValues[i]))
            if(len(data) != 0):
                assay.appendResponseBody(str(data),len(data))
            assay.processRequestHeaders()
            assay.processRequestBody()
            assay.processResponseHeaders()
            assay.processResponseBody()
            assay.processLogging(200)
            f = open('/tmp/debug.log','r')
            out = f.readlines()
            f.close()
            res = {"R":"Ran Succesfully", "X":out}
            x = json.dumps(res, ensure_ascii=False).encode('utf8')
            f = open('/tmp/debug.log','r+')
            f.truncate()
            f.close()
            return x

@app.route('/hello', methods=['GET', 'POST'])
def hello():
    return render_template('index.html',requestExample=req,responseExample=res,Version=str(modsecurity.ModSecurity().whoAmI()))



if __name__ == "__main__":
    app.debug = False
    app.run(host="192.168.112.223")


