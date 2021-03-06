#-------------------------------------------------------------------------------
# Name:        BIG loganalizer
# Purpose:
#
# Author:      Kuddusi
#
# Created:     07.09.2015
# Copyright:   (c) kudu 2015
# Licence:     <your licence>
# TODO: must catch kill signal and dump sessions
# TODO: must rename sessions.json after loading


#-------------------------------------------------------------------------------
import os
import subprocess
import shlex
import gzip
from datetime import datetime
import time
import Queue
from threading import Thread
import MySQLdb
import xml.etree.ElementTree
import sys

############ GLOBALS

TESTING=False # TODO: DONT FORGET TO TURN TESTING FALSE ON PROD!!!
ERROR=1
WARNING=3
NOTICE=4
INFO=5
DEBUG=6
LOG_SEVERITY=6 # TODO: in prod it should be ERROR severity
LOG_ENABLED=True
stopThread = False
logfileName="./processbiglogs.log"
dateTemplate="%Y-%m-%d %H:%M:%S"
sessions = {}
partialSessions = {} #they have only requests
partialSessions[0] = {} #  for the first time queries
completedsessions = Queue.Queue()
erroredsessions = Queue.Queue()
wrote2DB = 0
ignored = 0
dbExceptioned = 0
capture_path="/captures/pcaptest"
LOGS_PATH = "/captures/log/"
logfile=open(logfileName,"a+") #should be a+
currentRecordTime=""
methods=[]
fileSeq=1
#########
def timeStr(tstr,ms=True):
    #s="Mar 28, 2015 10:00:26.107652"
    if ms:
            tval =datetime.strptime(tstr,"%b %d, %Y %H:%M:%S.%f")

    else:
            tval =datetime.strptime(tstr,"%b %d, %Y %H:%M:%S")

    return tval.strftime("%Y-%m-%d %H:%M:%S")

def calculateDuration(playtime, teardowntime):

    platime = datetime.strptime(playtime,"%b %d, %Y %H:%M:%S.%f")
    teatime = datetime.strptime(teardowntime,"%b %d, %Y %H:%M:%S.%f")

    d = teatime - platime
    return d.total_seconds()

def log(str,severity=INFO):
    if (LOG_ENABLED and severity<=LOG_SEVERITY):
        now= datetime.now()
        logfile.write(now.strftime(dateTemplate) + " " + str + "\n")
        logfile.flush()

def findFiles():
#    findCommandStr="/usr/bin/find %s -mmin +2 -name \"*.pcap\"" % (capture_path,)
    findCommandStr="/usr/bin/find %s -mmin +2 -name \"*.log.gz\"" % (LOGS_PATH,)

    out = subprocess.check_output(shlex.split(findCommandStr)).splitlines()
##    newlist = sorted(out,key=os.path.getctime)
    out.sort()
##    log("Find Files result" + str(out))
##    if out:
##        out.pop()
    return out[:10]

def findFilesTest():
##    testFiles = ['/captures/logtest/20150331124927.pcap.log.gz','/captures/logtest/20150331131927.pcap.log.gz', '/captures/logtest/20150331171927.pcap.log.gz']
    testFiles = ['d:\\captures\\biglogs\\20161008141027.pcap.log.gz','d:\\captures\\biglogs\\20161008151027.pcap.log.gz',    'd:\\captures\\biglogs\\20161008161027.pcap.log.gz']
##    ,'d:\\captures\\biglogs\\20161008171027.pcap.log.gz','d:\\captures\\biglogs\\20161008171027.pcap.log.gz',
##    'd:\\captures\\biglogs\\20161008191027.pcap.log.gz','d:\\captures\\biglogs\\20161008201027.pcap.log.gz','d:\\captures\\biglogs\\20161008211027.pcap.log.gz']
    return testFiles

def inspectLine(ln):
    global currentRecordTime
    global methods
    global ignored
    global fileSeq
    global partialSessions

    v = ln.strip().split("|")
##    print ln
    ptime = v[0]
    if len(ptime) < 28:
        log("ERROR: time str is too short: " + ln,  DEBUG)
        return
    elif len(ptime)>30:
        ptime =ptime[:28]
        if ptime[-1]==",":
            ptime = ptime[:-1]

    if ptime[3:5]=="  ":
        ptime = ptime[:4] + "0" + ptime[5:]

    if len(v)!=11:
        log("parse error: invalid num of fields")
        return
    try:
        ipsrc = v[1]
        ipdst = v[2]
        portsrc = v[3]
        portdst = v[4]
        tcpstreamid = v[5]
        method = v[6]
        fulluri = v[7]
        soapaction = v[8]
        responsecode= v[9]
        data = v[10]
    except:
        erroredsessions.put("PARSER ERROR: Wrong line:" +ln)
        return
###################################3

    if method: #This is a request
##        if soapaction=="CAI3G#Login"  or soapaction=="CAI3G#Logout":
##            return
        sessionId = "%d_%s_%s_%s" % (fileSeq,ipsrc,ipdst,portsrc)
##        log(sessionId+ ": REQUEST",DEBUG)
        if not sessionId in sessions: #This is new request
            curses = {}
            sessions[sessionId]=curses
            pass
        else: #former request did not have response
            erroredsessions.put("former request did not have response SID:" % sessionId)
            ignored +=1
            return
        curses["ipsrc"]=ipsrc
        curses["ipdst"]=ipdst
        curses["portsrc"]=portsrc
        curses["portdst"]=portdst
        curses["tcpstreamid"]=tcpstreamid
        curses["method"]=method
        curses["fulluri"]=fulluri
        curses["soapaction"]=soapaction.replace('"','')
        curses["request_data"]=data
        curses["request_time"]=ptime
##        curses["ipsrc"]=ipsrc




    else: #This is response
##        if data.find("LoginResponse")!=-1 or data.find("LoginResponse")!=-1:
##            return
        sessionId = "%d_%s_%s_%s" % (fileSeq, ipdst,ipsrc,portdst)
##        log(sessionId+ ": RESPONSE",DEBUG)
        if sessionId in sessions: #we found the session
            curses = sessions.pop(sessionId)
        else:
            sessionId = "%s_%s_%s" % (ipdst,ipsrc,portdst)
            if sessionId in partialSessions[fileSeq-1]: #we found in older files
                curses = partialSessions[fileSeq-1].pop(sessionId)
                log("Found Request from older pcap files sid=%s" % sessionId, WARNING )
            else:
##                erroredsessions.put("Could not find Response's Request for sessionid=%s" % sessionId)
                ignored +=1
                return
        curses["responsecode"]=responsecode
        curses["response_data"]=data
        curses["response_time"]=ptime
##        print "completed a session ", sessionId
##        log(curses["request_time"])
        curses["response_duration"]=calculateDuration(curses["request_time"],curses["response_time"])

        subscriberId = None
        userId = None
        newOffer = None
        oldOffer = None
        bigSessionId = None
        faultCode = None
        regCode = None
        faultString =None

        try:
            e = xml.etree.ElementTree.fromstring( curses["request_data"].replace(";;","") )
            subsElem  = e.find('.//{http://schemas.ericsson.com/cai3g1.2/}subscriberId')
            subscriberId = subsElem.text if subsElem is not None else None
            userElem  = e.find('.//{http://schemas.ericsson.com/cai3g1.2/}userId')
            userId = userElem.text if userElem is not None else None
            offerList  = e.find('.//{http://cai3g.iap.iptv.ericsson.com/iptv_provisioning_subscriber/}offerList')
            regCodeElem  = e.find('.//{http://cai3g.iap.iptv.ericsson.com/iptv_provisioning_subscriber/}registrationCode')
            regCode = regCodeElem.text if regCodeElem is not None else None

            newOffer = None
            oldOffer = None
            if offerList is not None:
                for u in offerList:
                    if "delete" in u.attrib:
                        if u.attrib['delete']=="true":
                            oldOffer = u.attrib['offerId']
                        else:
                            newOffer = u.attrib['offerId']
                    else: #delete is false
                        if newOffer is not None:
                            newOffer = newOffer + "+" +u.attrib['offerId']
                        else:
                            newOffer = u.attrib['offerId']
            bigSessionId = None
            sidElem = e.find('.//{http://schemas.ericsson.com/cai3g1.2/}SessionId')
            bigSessionId = sidElem.text if sidElem is not None else None
            e=None

            if responsecode!= "200":
                r = xml.etree.ElementTree.fromstring(curses["response_data"].replace(";;",""))

                faultElem = r.find('.//{http://schemas.ericsson.com/cai3g1.2/}faultcode')
                faultCode = faultElem.text if faultElem is not None else None

                fsElem = r.find('.//{http://schemas.ericsson.com/cai3g1.2/}reasonText')
                faultString = fsElem.text if fsElem is not None else None
                if faultCode is None:
                    fsElem = r.find('.//faultstring')
                    faultCode = fsElem.text if fsElem is not None else None
                r=None

##            log("%s, %s, %s,%s,%s,%s,%s,regCode=%s"% ( bigSessionId, soapaction, subscriberId, userId,newOffer,oldOffer,faultCode,regCode ))
        except Exception as e:
            erroredsessions.put("Exception %s in %s" % (str(e),curses["request_data"]))

        curses["subscriberId"] = subscriberId
        curses["userId"] = userId
        curses["newOffer"] = newOffer
        curses["oldOffer"] = oldOffer
        curses["bigSessionId"] = bigSessionId
        curses["faultCode"] = faultCode
        curses["regCode"] = regCode
        curses["faultString"] = faultString

        if curses["soapaction"] in ('CAI3G#Login', 'CAI3G#Logout'): #Dont store Login or Logout requests
            curses = None
            return
        elif curses["soapaction"] in ('CAI3G#Get'): #Dont store Get's Result
            curses["request_data"]=None
            shortText= ""
            if responsecode == "200": #write Gets summary
                try:
                    r = xml.etree.ElementTree.fromstring(curses["response_data"].replace(";;",""))
                    offerList  = r.find('.//{http://cai3g.iap.iptv.ericsson.com/iptv_provisioning_subscriber/}offerList')
                    if offerList is not None:
                        shortText+="Offers:"
                        for u in offerList:
                            shortText+= "\n" + u.attrib['offerId']

                    bootstrap  = r.find('.//{http://cai3g.iap.iptv.ericsson.com/iptv_provisioning_subscriber/}bootstrap')
                    if bootstrap is not None:
                        shortText+= "\nBootstraps:"
                        for u in bootstrap:
                            shortText+=  "\nReg Code:" + u.attrib['registrationCode'] + " Equip Id:" + u.attrib['equipmentId']

                    equipments  = r.find('.//{http://cai3g.iap.iptv.ericsson.com/iptv_provisioning_subscriber/}equipment')
                    if equipments is not None:
                        if len (list(equipments)) > 0:
                            shortText+="\nEquipments Provised:"
                            for u in equipments:
                                shortText+= "\n" +u.text
                except Exception as e:
                    erroredsessions.put("Exception %s in %s" % (str(e),curses["request_data"]))
                    shortText = None
                r=None
            else: # if response is different from 200. do nothing.
                shortText=None

            curses["response_data"]=shortText

            ignored += 1

        completedsessions.put(curses)
        r=None
        curses = None


def totimestamp(dt, epoch=datetime(1970,1,1)):
    td = dt - epoch
    return td.total_seconds()

def totimestampfromstring(str1):
    return totimestamp(datetime.strptime(str1,"%b %d, %Y %H:%M:%S.%f"))

def clearPartialSessions():
    global sessions
    global partialSessions
    global fileSeq


    partialSessions[fileSeq] = sessions
    sessions = None
    sessions = {}
    log("Length of partial sessions is %d" % len(partialSessions[fileSeq] ))
    oldseq = fileSeq-1
    if oldseq in partialSessions:
        partialSessions.pop(oldseq) #clear previous sessions


def getField(array1,field,integer=False,double=False):
    if array1.has_key(field) and array1[field] is not None :
        if double:
            return str(array1[field])
        elif integer:
            return str(int(array1[field]))
        else:
            if array1[field].find('"')!=-1:
                return "'%s'" % (MySQLdb.escape_string(array1[field]),)
            return "'%s'" % (array1[field],)
    else:
        return "NULL"
def getField2(array1,field):
    if array1.has_key(field):
      return array1[field]
    else:
      return ""
def getTime(array1,field):
    if array1.has_key(field):
        return "'%s'" % (timeStr(array1[field]),)
    else:
        return "NULL"

def cdrFormat(cdr):
    seperator="|"
    fieldList = [getField2(cdr,"request_time"),getField2(cdr,"response_time"),getField2(cdr,"response_duration"),
        getField2(cdr,"soapaction"), getField2(cdr,"subscriberId"), getField2(cdr,"userId"),  getField2(cdr,"newOffer"), getField2(cdr,"oldOffer"), getField2(cdr,"bigSessionId"),
        getField2(cdr,"responsecode"), getField2(cdr,"ipsrc"),getField2(cdr,"ipdst"),getField2(cdr,"portsrc"),
        getField2(cdr,"portdst"),getField2(cdr,"tcpstreamid"),
        getField2(cdr,"fulluri"), getField2(cdr,"request_data"),getField2(cdr,"response_data")]
    return seperator.join([str(x) for x in fieldList])

def mysqlFormat(cdr):
##    print cdr
    strHead = "INSERT INTO Biglogs.livemain VALUES(%s)"
    #intFields = ["duration","getparametercount"]
    #dateFields = ["setuptime","playtime", "endtime"]

    Values="NULL,%s,%s, %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s" % (getTime(cdr,"request_time"),
        getTime(cdr,"response_time"),
        getField(cdr,"response_duration",False,True),
        getField(cdr,"ipsrc"),
        getField(cdr,"ipdst"),
        getField(cdr,"portsrc",True),
        getField(cdr,"portdst",True),
        getField(cdr,"soapaction"),
        getField(cdr,"responsecode",True),
        getField(cdr,"faultCode"),
        getField(cdr,"subscriberId"),
        getField(cdr,"userId"),
        getField(cdr,"newOffer"),
        getField(cdr,"oldOffer"),
        getField(cdr,"regCode")
            )
    return strHead % (Values,)

def mysqlFormatDetailTable(cdr,paketid):
##    print cdr
    strHead = "INSERT INTO Biglogs.livedetail VALUES(%s)"
    #intFields = ["duration","getparametercount"]
    #dateFields = ["setuptime","playtime", "endtime"]

    Values="%s,%s, %s, %s, %s,%s,%s" % (paketid,
        getField(cdr,"tcpstreamid",True),
        getField(cdr,"bigSessionId",True),
        getField(cdr,"fulluri"),
        getField(cdr,"faultString"),
        getField(cdr,"request_data"),
        getField(cdr,"response_data") )
    return strHead % (Values,)

def logSqlError(f,se,e):
    try:
        f.write(datetime.now().strftime("%Y-%m-%d %H:%M:%S :"))
        f.write(e)
        f.write("\nQuery:")
        f.write(se)
        f.write("\n")
    except Exception,e:
        print "SQL Exception in query:",str(e)
        f.flush()
def logSessionError(f,errorStr):
     f.write(datetime.now().strftime("%Y-%m-%d %H:%M:%S :"))
     f.write(errorStr + "\n")
     f.flush()


def dumpErroredSessions2File():
    #TODO: may be we need to write them to DB
    log("Dump Errored Session thread is started")
    errFile = open("sessionerrors.log","w+") #TODO: in prod it should be a+
    while not stopThread:
        try:
            errored = erroredsessions.get(timeout=1)
        except Queue.Empty:
            continue
        logSessionError(errFile,str(errored))
        erroredsessions.task_done()
    if errFile.closed:
        errFile.close()
    log("Dump Errored Session thread is started")

def dumpSessions2DB():
    global wrote2DB
    global dbExceptioned

    TESTING1=False #TODO: in prod it should be False
    log("Dump thread is started\n")
    db = MySQLdb.connect('localhost', 'biglogger', 'VOD1234log', 'Biglogs')
##    db.escape_strings()
    if not db:
        log("Could not connect to DB",ERROR)
        #TODO: We must stop main process too.. Find a way.
        return
    log("connected to mysql\n")
    sqlLF = open("sqlerrors.log","w+") #TODO: in prod it should be a+
    if TESTING1:
        cursor = db.cursor()
        cursor.execute("TRUNCATE TABLE Biglogs.livemain")
        cursor.execute("TRUNCATE TABLE Biglogs.livedetail")
        db.commit()


    while not stopThread:
        if db.open:
            try:
                completed = completedsessions.get(timeout=1)
            except Queue.Empty:
                continue

            queryStr = mysqlFormat(completed)

            try:
                cursor = db.cursor()
                if cursor.execute(queryStr):

                    paketId = cursor.lastrowid
##                    cursor = db.cursor()
                    query2 = mysqlFormatDetailTable(completed,paketId)
##                    log(query2)
                    cursor.execute(query2)

                    wrote2DB += 1
                    if wrote2DB % 100:
                        db.commit()
              #TODO: We need to find a way to record the count of inserted rows
                    completedsessions.task_done()
            except AttributeError, e:
                if not db.open:
                  log("Mysql connection is closed. Try to reconnect..")
                  db = MySQLdb.connect('localhost', 'biglogger', 'VOD1234log', 'Biglogs')
                logSqlError(sqlLF,"Attribute Error: " + queryStr,str(e))
##                cursor = db.cursor()
##                cursor.execute(queryStr)
            except MySQLdb.OperationalError, e:##
               if not db.open:
                  log("Mysql connection is closed. Try to reconnect..")
                  db = MySQLdb.connect('localhost', 'biglogger', 'VOD1234log', 'vodlog')
               logSqlError(sqlLF,"Operation Error: " + queryStr,str(e))
            except MySQLdb.IntegrityError, e:
                logSqlError(sqlLF,queryStr,str(e))
                dbExceptioned += 1
            except MySQLdb.Error, e:
               logSqlError(sqlLF,queryStr,str(e))
               dbExceptioned += 1
            except MySQLdb.Warning, e:
               logSqlError(sqlLF,queryStr,str(e))
               dbExceptioned += 1
            except Exception,e:
               logSqlError(sqlLF,queryStr,"Unknown mysql Error:" + str(e))
               dbExceptioned += 1
                #db.rollback()

        else:
            log("Mysql connection is closed. Try to reconnect..")
            db =MySQLdb.connect('localhost', 'biglogger', 'VOD1234log', 'Biglogs')

    log("Dump thread is stopped\n")
    if db:
        db.close()
    if not sqlLF.closed:
        sqlLF.close()

def dumpSessions2File():
    global wrote2DB
    print "Dump thread is started\n"
    testout = open("testout","w+")

    while not stopThread:
        try:
           completed = completedsessions.get(timeout=1)
        except Queue.Empty:
                continue
        if completed == -1:
            break

##        print completed["tcpstreamid"]
##        testout.write(cdrFormat(completed)+"\n")

        testout.write(mysqlFormat(completed) + "\n")
##        testout.write(mysqlFormatDetailTable(completed,99999) + "\n")

        testout.flush()
##        completedsessions.task_done()
        wrote2DB += 1

    testout.close()
    print "Dump thread is stopped\n"
"""
    errorfile= open("errors","w+")
    while erroredsessions:
        e = erroredsessions.pop(0)
        errorfile.write(cdrFormat(e)+"\n")
    errorfile.close()

    if len(completedsessions)>0:
        log("Completed Dumping is not successfull %d remains\n" % len(completedsessions))
    if len(erroredsessions)>0:
        log("Errored Dumping is not successfull %d remains\n" % len(erroredsessions))
"""
def pcap2Log(pcapfile):
    commandStr="/captures/scripts/pcap2log.sh " + pcapfile
    subprocess.check_output(shlex.split(commandStr))
    (dir1, pcapfilename) = os.path.split(pcapfile)
    return LOGS_PATH + pcapfilename[9:] + ".log.gz"

def loadSessions():
    import json
    global sessions
    try:
        f = open("partialsessions.json","r")
    except:
        return
    if f:
        sessions=json.load(f)
        log ("%d sessions are loaded from file" % (len(sessions),) )
        f.close()


def writeSessions():
    import json
    f = open("partialsessions.json","w+")
    json.dump(partialSessions,f)
    f.close()


def getConfig():
    global LOG_SEVERITY
    retVal = False

   # log(",")

    fn = open("./processlogs.config")
##    log( str(fn.readlines()))
    for ln in fn.readlines():
##        log( "line: "+ ln)
        if "stop" in ln:
            q = ln.split("stop=")[1].strip()
            if q=="1":
                retVal = True
        elif "severity" in ln:
            LOG_SEVERITY = int(ln.split("severity=")[1].strip())
    fn.close()
    return retVal

# # # # # # # # # # #
## ver: 1.001
def main():
    global stopThread
    global fileSeq
    if LOG_ENABLED:
        log("Log analizer has started--------------------------------------------")
    # This is a throwaway variable to deal with a python bug
    throwaway = datetime.strptime('20110101','%Y%m%d')

# MAIN LOOP
    counter=True
    th1 = Thread(target=dumpSessions2DB)
    th1.daemon = True
    th1.start()

    th2 = Thread(target=dumpErroredSessions2File)
    th2.daemon = True
    th2.start()

    while counter: #true MAIN LOOP
        line = sys.stdin.readline()
        try:
            inspectLine(line.strip())
##            log(line)
        except KeyboardInterrupt:
            break
        except Exception as e:
##                        log("PARSER ERROR:" + line,DEBUG)
            erroredsessions.put(str(e))
            continue



    #rename log file
    clearPartialSessions()
    log("Partial:%d\tErrd:%d\tIgnd:%d\tComptd:%d\tWr2DB:%d\tDBExcept:%d" % (
        len(partialSessions[fileSeq]),erroredsessions.qsize(),ignored,completedsessions.qsize(),wrote2DB,dbExceptioned ) )
    fileSeq += 1

##            if TESTING:
##                counter=False
##                completedsessions.put(-1)

##    log("Waiting for threads to stop")
###    th1.daemon = False
###    th2.daemon = False
##
##    th1.join()
##    th2.join()

##    log("Partial:%d\tErrd:%d\tIgnd:%d\tComptd:%d\tWr2DB:%d\tDBExcept:%d" % (
##              len(partialSessions[fileSeq]),erroredsessions.qsize(),ignored,completedsessions.qsize(),wrote2DB,dbExceptioned ) )
##    log("Storing incomplete sessions")
##    writeSessions()
##    log("Stopped normally----------------------------")
    logfile.close()

if __name__ == '__main__':
    main()
