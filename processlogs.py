#-------------------------------------------------------------------------------
# Name:        loganalizer
# Purpose:
#
# Author:      Kuddusi
#
# Created:     28.03.2015
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

############ GLOBALS

TESTING=False # TODO: DONT FORGET TO TURN TESTING FALSE ON PROD!!!
ERROR=1
WARNING=3
NOTICE=4
INFO=5
DEBUG=6
LOG_SEVERITY=5 # TODO: in prod it should be ERROR severity
LOG_ENABLED=True
stopThread = False
logfileName="./processlogs.log"
dateTemplate="%Y-%m-%d %H:%M:%S"
sessions = {}
setups = {}
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
    return out[:5]

def findFilesTest():
    testFiles = ['/captures/logtest/20150331124927.pcap.log.gz','/captures/logtest/20150331131927.pcap.log.gz',
    '/captures/logtest/20150331171927.pcap.log.gz']
    return testFiles

def inspectLine(ln):
    global currentRecordTime
    global methods
    global ignored

    v = ln.split("|")
##    print ln
    ptime = v[0]
    if len(ptime) < 28:
        log("ERROR: time str is too short: " + ln,  DEBUG)
        return
    elif len(ptime)>30:
        ptime =ptime[:29]
        if ptime[-1]==",":
            ptime = ptime[:-1]

    if ptime[3:5]=="  ":
        ptime = ptime[:4] + "0" + ptime[5:]

    if len(v)!=10:
        return
    try:
        ipsrc = v[1]
        ipdst = v[2]
        srcport = v[4]
        dstport = v[5]
        method = v[6]
        status = v[7]
        transport= v[8][21:]
        data = v[9]


        if "CSeq" in data:
            cseq = data.split("CSeq:")[1].split(";")[0][1:]
        else:
            return
    except:
        print ln
        return


    if v[3]:
        sid = v[3].split(";")[0].split(",")[0]
    else:
        #we dont have sessionid so it must be SETUP packet
        if method:
            if method=="SETUP":
                id=ipsrc+srcport
                setups[id]={}
                setups[id]["setuptime"]=ptime
                setups[id]["ip"]=ipsrc

                if data.find("AssetUid") > 0:
                    pos = data.find("AssetUid")
                    assetId=data[pos+9:pos+17]
                    setups[id]["assetid"]=assetId

                if data.find("device-id") > 0:
                    pos = data.find("device-id")
                    macid=data[pos+10:pos+22]
                    setups[id]["mac"]=macid
                return
            else:
                #other messages like OPTIONS, DESCRIBE, PING has come
                log("Ignored method came with no session id\n" + ln, DEBUG)
                return
        elif status:
            id=ipdst+dstport

            if setups.has_key(id):
                setups[id]["lasterror"]=status
                setups[id]["evorder"] = "S-" + status
                setups[id]["lastannounce_msg"] = data
                setups[id]["completed"] = 2
                setups[id]["endtime"] = ptime
                setups[id]["duration"] = 0
                setups[id]["lastmsg_time"]=ptime
##                setups.pop(id)
            else:
                #no session, no setup, what we can we do?
                pass

    #we have session key from line
    if (not sessions.has_key(sid)):
       if method in ["SETUP","PLAY","PAUSE","TEARDOWN","PAUSE,TEARDOWN","ANNOUNCE","REDIRECT"]:
           #add to sessions
           sessions[sid]={}
           sessions[sid]["sessionid"]=sid
           this_is_first_packet = True
       elif status=="200" and transport:
           #add to sessions
           sessions[sid]={}
           sessions[sid]["sessionid"]=sid
           this_is_first_packet = True
       elif status!="200":
           #do not add to sessions
           #log("ERROR: Error packet being firsrt with session\n"+ln)
           return
       else:
            return
    #we have found session in our memory
    ss=sessions[sid]
    if cseq>0:
        ss["lastCSeq"]=cseq

    if method:
        #this packet is REQUEST
        ss["ip"]=ipsrc
        ss["mac"]=sid[:12]

        if not ss.has_key("assetid"):
            if data.find("AssetUid") > 0:
                pos = data.find("AssetUid")
                assetId=data[pos+9:pos+17]
                ss["assetid"]=assetId

        if method=="PLAY":
            if int(cseq)==2:
                #this is first play packet
                ss["playtime"]=ptime
            else:
                #this is one of subsequent plays
                #write only once.
                if not ss.has_key("playtime"):
                    ss["playtime"]=ptime

            if ss.has_key("evorder"):
                ss["evorder"]=ss["evorder"]+ "P"
            else:
                ss["evorder"]="P"

        elif method=="SETUP":
            ss["setuptime"]=ptime

            if ss.has_key("evorder"):
                ss["evorder"]=ss["evorder"]+ "s"
            else:
                ss["evorder"]="s"

        elif method=="TEARDOWN":
            #ss["duration"]=X
            ss["endtime"]=ptime
            ss["endtime_ts"]=totimestampfromstring(ptime)
            ss["teardown_cseq"]=cseq
            ss["completed"]=1

            if ss.has_key("evorder"):
                ss["evorder"]=ss["evorder"]+ "T"
            else:
                ss["evorder"]= "T"
            if ss.has_key("playtime"):
                ss["duration"] = calculateDuration(ss["playtime"],ss["endtime"])
            if not ss.has_key("setuptime"):
                    if ss.has_key("playtime"):
                        ss["setuptime"]=ss["playtime"]
                    else:
                        ss["setuptime"]=ss["endtime"]

        elif method=="ANNOUNCE":
            if ss.has_key("lastannounce_msg"):
                ss["lastannounce_msg"] = " + " + ss["lastannounce_msg"] + data.split(";")[2]
            else:
                 ss["lastannounce_msg"]=data.split(";")[2]
            ncode=data.split(";")[2].split(":")[1][1:5]
            if ss.has_key("evorder"):
                ss["evorder"]=ss["evorder"]+ "A" + ncode
            else:
                ss["evorder"]= "A" + ncode
            #anonce msg ekle
        elif method=="GET_PARAMETER":
            if ss.has_key("getparamkeys"):
                ss["getparamkeys"].append(cseq)
            else:
                ss["getparamkeys"]=[]
                ss["getparamkeys"].append(cseq)
        elif method=="PAUSE":
            if ss.has_key("evorder"):
                ss["evorder"]=ss["evorder"]+ "p"
            else:
                ss["evorder"]="p"
        elif method=="REDIRECT":
            if ss.has_key("evorder"):
                ss["evorder"]=ss["evorder"]+ "R"
            else:
                ss["evorder"]="R"
        elif "TEARDOWN" in method:
            #ss["duration"]=X
##            print ln
            if len(ptime)>30:
                ptime =ptime[:29]
            ss["endtime"]=ptime

            ss["endtime_ts"]=totimestampfromstring(ptime)
            ss["teardown_cseq"]=cseq
            ss["completed"]=1

            if ss.has_key("evorder"):
                ss["evorder"]=ss["evorder"]+ "t"
            else:
                ss["evorder"]= "t"
            if ss.has_key("playtime"):
                ss["duration"] = calculateDuration(ss["playtime"],ss["endtime"])
            if not ss.has_key("setuptime"):
                    if ss.has_key("playtime"):
                        ss["setuptime"]=ss["playtime"]
                    else:
                        ss["setuptime"]=ss["endtime"]
            if not (method in methods):
                methods.append(method)
                log("TEARDOWN COMPLEX METHOD:%s, Entire message: %s" % (method,ln),DEBUG )

        else:
            #log("unknown method came with session id:" + sid + "\n" + ln)
            if not (method in methods):
                methods.append(method)
                log("UNKNOWN METHOD:%s, Entire message: %s" % (method,ln),DEBUG)
            ignored += 1
            return
        ss["lastmsg_time"]=ptime

    elif status:
#this packet is RESPONSE
        if status=="200":
            if transport:
                #this is 200 OK response to SETUP
                ss["transport"]=transport
                id=ipdst+dstport
                if "source" in transport:
                    ss["fmsip"] = transport.split("source=")[1].split(";")[0]
                if setups.has_key(id):
                    ss["setuptime"]=setups[id]["setuptime"]
                    currentRecordTime = ptime
                    setups.pop(id)

                    if ss.has_key("evorder"):
                        ss["evorder"]="S+" + ss["evorder"]
                    else:
                        ss["evorder"]="S+"
                else:
                    #setup is unknown, lets fake setuptime
                    ss["setuptime"]=ptime
                    if ss.has_key("evorder"):
                        ss["evorder"]="+" + ss["evorder"]
                    else:
                        ss["evorder"]="+"
            else:
                #there is no transport
                if ss.has_key("getparamkeys"):
                    if cseq in ss["getparamkeys"]:
                        x=1
                    else:
                        if ss.has_key("evorder"):
                            ss["evorder"]= ss["evorder"] + "+"
                        else:
                            ss["evorder"]= "+"
                else:
                    if ss.has_key("evorder"):
                        ss["evorder"]= ss["evorder"] + "+"
                    else:
                        ss["evorder"]= "+"

                #else:
                #    if this_is_first_packet:
                 #       pass
                if  ss.has_key("completed"):
                    ss["completed"]+=1
        else:
            #we have error or notification
            #todo maybe we can do more here
            if ss.has_key("evorder"):
                ss["evorder"]= ss["evorder"] + "-"+status
            else:
                ss["evorder"]= "-"+status
            ss["lasterror"]= status

            if ss.has_key("lastannounce_msg"):
                ss["lastannounce_msg"] = " + " + ss["lastannounce_msg"] + data
            else:
                ss["lastannounce_msg"]= data


        #move completed sessions to another array


##        if ss.has_key("completed"):
##            if ss["completed"] >=2:
##                if ss.has_key("getparamkeys"):
##                    ss["getparametercount"]=len(ss["getparamkeys"])
##                completedsessions.put(sessions.pop(sid))

def totimestamp(dt, epoch=datetime(1970,1,1)):
    td = dt - epoch
    return td.total_seconds()

def totimestampfromstring(str1):
    return totimestamp(datetime.strptime(str1,"%b %d, %Y %H:%M:%S.%f"))

def clearPartialSessions():
##    nowts = totimestamp(datetime.now())

    nowts = totimestampfromstring(currentRecordTime)
    maxlen=1
    maxdata=""
    maxsid=""
    for sid in sessions.keys():
        sdata=sessions[sid]
        # for all sessions calculate getparametercount
        if sdata.has_key("getparamkeys"):
            sdata["getparametercount"]=len(sdata["getparamkeys"])
        else:
            sdata["getparametercount"]=0

        if sdata.has_key("completed"): #sessions do have endtime
            if sdata["completed"]>=1:
                if (nowts - sdata["endtime_ts"]) > 120:
                    completedsessions.put(sessions.pop(sid))

        elif sdata.has_key("setuptime"): #sessions dont have endtime but setup time
            if (nowts - totimestampfromstring(sdata["setuptime"])) > 14400:
                if (sdata["getparametercount"]) > 1:
                    sdata["duration"]= calculateDuration(sdata["setuptime"], sdata["lastmsg_time"])
                else:
                    sdata["duration"]=0

                completedsessions.put(sessions.pop(sid))
        elif sdata.has_key("playtime"): #session dont have setup, endtime but have playtime
            if (nowts - totimestampfromstring(sdata["playtime"])) > 14400:
                sdata["setuptime"]=sdata["playtime"]
                if (sdata["getparametercount"]) > 1:
##                    print sdata
                    sdata["duration"]= calculateDuration(sdata["setuptime"], sdata["lastmsg_time"])
                else:
                    sdata["duration"]=0

                completedsessions.put(sessions.pop(sid))
        else: # sessions dont have end,setup,play
            erroredsessions.put(sessions.pop(sid))
        if len(sdata["evorder"]) > maxlen:
            maxlen = len(sdata["evorder"])
            maxdata = sdata["evorder"]
            maxsid = sid

    for setupid in setups.keys():
        setupdata=setups[setupid]
        if setupdata.has_key("completed"):
            if setupdata["completed"]>=2:
                completedsessions.put(setups.pop(setupid))

        elif (nowts - totimestampfromstring(setupdata["setuptime"])) > 14400:
                setupdata["duration"]=0 #TODO: we can check if it is true alltime
                completedsessions.put(setups.pop(setupid))

    log("Maximum event order length is %d: sessionid:%s Event order is:%s" % (maxlen,maxsid,maxdata),DEBUG)

def getField(array1,field,integer=False):
    if array1.has_key(field):
        if integer:
            return array1[field]
        else:
            if len(array1[field]) < 500:
                return "'%s'" % (array1[field],)
            else:
                return "'%s'" % (array1[field][0:249] + array1[field][-249:],)

    else:
        if integer:
            return 0
        else:
            return "NULL"
def getTime(array1,field):
    if array1.has_key(field):
        return "'%s'" % (timeStr(array1[field]),)
    else:
        return "NULL"

def cdrFormat(cdr):
    seperator="|"
    fieldList = [getField(cdr,"setuptime"), getField(cdr,"mac"),getField(cdr,"ip"),getField(cdr,"sessionid"),
        getField(cdr,"assetid"),getField(cdr,"fmsip"),getField(cdr,"duration"),getField(cdr,"playtime"),getField(cdr,"endtime"),
        getField(cdr,"evorder"),getField(cdr,"lasterror"),getField(cdr,"getparametercount"),getField(cdr,"lastannounce_msg")]
    return seperator.join([str(x) for x in fieldList])

def mysqlFormat(cdr):
    strHead = "INSERT INTO vodlog.cdr VALUES(%s)"
    #intFields = ["duration","getparametercount"]
    #dateFields = ["setuptime","playtime", "endtime"]

    Values="NULL,%s,%s, %s,%s,%s,%s,%d,%s,%s,%d,%s,%s,%s,%s" % (getTime(cdr,"setuptime"),
        getField(cdr,"mac"),
        getField(cdr,"ip"),
        getField(cdr,"sessionid"),
        getField(cdr,"assetid"),
        getField(cdr,"fmsip"),
        getField(cdr,"duration",True),
        getTime(cdr,"playtime"),
        getTime(cdr,"endtime"),
        getField(cdr,"getparametercount",True),
        getField(cdr,"evorder"),
        getField(cdr,"lasterror"),
        getField(cdr,"lastannounce_msg"),
        getTime(cdr,"lastmsg_time")    )
    return strHead % (Values,)

def logSqlError(f,se,e):
        f.write(datetime.now().strftime("%Y-%m-%d %H:%M:%S :"))
        f.write(e)
        f.write("\n\   " + se + "\n")
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
    db = MySQLdb.connect('localhost', 'vod', 'VOD1234log', 'vodlog')
    if not db:
        log("Could not connect to DB",ERROR)
        #TODO: We must stop main process too.. Find a way.
        return
    log("connected to mysql\n")
    sqlLF = open("sqlerrors.log","w+") #TODO: in prod it should be a+
    if TESTING1:
        cursor = db.cursor()
        cursor.execute("TRUNCATE TABLE vodlog.cdr")
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
                    db.commit()
                    wrote2DB += 1
              #TODO: We need to find a way to record the count of inserted rows
                    completedsessions.task_done()
            except AttributeError, e:
                if not db.open:
                  log("Mysql connection is closed. Try to reconnect..")
                  db = MySQLdb.connect('localhost', 'vod', 'VOD1234log', 'vodlog')
                logSqlError(sqlLF,"Attribute Error: " + queryStr,str(e))
##                cursor = db.cursor()
##                cursor.execute(queryStr)
            except MySQLdb.OperationalError, e:##
               if not db.open:
                  log("Mysql connection is closed. Try to reconnect..")
                  db = MySQLdb.connect('localhost', 'vod', 'VOD1234log', 'vodlog')
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
            except:
               logSqlError(sqlLF,queryStr,"Unknown mysql Error:")
               dbExceptioned += 1
                #db.rollback()

        else:
            log("Mysql connection is closed. Try to reconnect..")
            db = MySQLdb.connect('localhost', 'vod', 'VOD1234log', 'vodlog')

    log("Dump thread is stopped\n")
    if db:
        db.close()
    if not sqlLF.closed:
        sqlLF.close()

def dumpSessions2File():
    print "Dump thread is started\n"
    testout = open("testout","w+")

    while not stopThread:
        completed = completedsessions.get()
        #testout.write(cdrFormat(completed)+"\n")
        testout.write(mysqlFormat(completed) + "\n")
        testout.flush()
        completedsessions.task_done()
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
    json.dump(sessions,f)
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
    loadSessions()
    print "Bismillah. Waiting to launch.. 10 seconds remaining..\n"
    time.sleep(10)
    while counter: #true
    #fileArray= ['e:\\captures\\20150328231927.pcap.log.gz']
        if getConfig():
            log("Stop command is received from config file. Stopping...\n")
            stopThread=True
            counter=False
            break
        if TESTING:
            fileArray = findFilesTest()
        else:
            fileArray = findFiles()

        if len(fileArray)==0:
            time.sleep(60)
            logfile.write(".")
            logfile.flush()

            continue
        else:
            log("\nFound %d files. Processing..." % len(fileArray))
            for fn in fileArray:
            #PROCESSING LOG FILES

##                log("Setups:%d\tPartial:%d\tErrored:%d\tCompleted:%d\tWrote2DB:%d\n" % (len(setups),
##                    len(sessions),erroredsessions.qsize(),completedsessions.qsize(),wrote2DB ) )

                newLogFileName = fn
                log("Opening file " + newLogFileName)
                f = gzip.open(newLogFileName, 'rb')
                for line in f:
                    try:
                        inspectLine(line)
                    except:
                        log("PARSER ERROR:" + line,DEBUG)
                        continue

                f.close()
                log("Closed file " + newLogFileName)
                #rename log file
                os.rename(newLogFileName,newLogFileName[0:-2]+"db.gz")
                log("Setups:%d\tPartial:%d\tErrd:%d\tIgnd:%d\tComptd:%d\tWr2DB:%d\tDBExcept:%d" % (len(setups),
                    len(sessions),erroredsessions.qsize(),ignored,completedsessions.qsize(),wrote2DB,dbExceptioned ) )

            log("Session clearing is started")
            clearPartialSessions()
            log("Session clearing is finished")
            log("Setups:%d\tPartial:%d\tErrd:%d\tIgnd:%d\tComptd:%d\tWr2DB:%d\tDBExcept:%d" % (len(setups),
              len(sessions),erroredsessions.qsize(),ignored,completedsessions.qsize(),wrote2DB,dbExceptioned ) )
            log("Unhandled methods:" + str(methods),DEBUG)

           #PROCESSING FILES STOP
            if TESTING:
                counter=False

    log("Waiting for threads to stop")
#    th1.daemon = False
#    th2.daemon = False
    th1.join()
    th2.join()
    log("Storing incomplete sessions")
    writeSessions()
    log("Stopped normally----------------------------")
    logfile.close()



if __name__ == '__main__':
    main()
