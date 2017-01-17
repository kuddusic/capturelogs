#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      189873
#
# Created:     06.01.2017
# Copyright:   (c) 189873 2017
# Licence:     <your licence>
#-------------------------------------------------------------------------------
from config import Config
import Queue
from threading import Thread
import MySQLdb
from datetime import datetime,timedelta
from time import sleep
from argela import Argela

import logging
import logging.config

logging.config.fileConfig("logging.ini")
logging._srcfile=None
logging.logThreads = 1
logging.logProcesses = 1
stopThread = False
logger = logging.getLogger('VLOG')
debugLogger = logging.getLogger('DEBUGLOG')


class Worker(Thread):
    def __init__(self, thread_no,  queue):
        super(Worker, self).__init__()
        self.name = "Worker-%d" % thread_no
        logger.warn("%s has initialized", self.name)
        self.queue = queue
        self.db = None
        self.argela = Argela(Config.useStagingArgla)

    def connect2DB(self,reconnect=True):
        if reconnect:
            logger.warn("Mysql connection is closed. Try to reconnect..")
        return MySQLdb.connect(Config.dbServer, Config.dbUser, Config.dbPass, Config.dbName)
    def run(self):
        logger.warn("%s is running", self.name)
        self.db = self.connect2DB()
        while(not stopThread):
            try:
                j = self.queue.get(timeout=1.0)
##                debugLogger.debug(j)
##                sleep(1)
                method = j[fields.soapaction]
##                debugLogger.debug("method is=%s" % method)
                self.doAction(method,j)

                self.queue.task_done()
            except Queue.Empty:
                continue
        logger.warn("%s is stopped", self.name)

    def doAction(self,method,task):
        subscriberid = task[fields.subscriberId]
        serviceid = task[fields.goAccountId]
        newOfferid = task[fields.newOffer]
        paketid = task[fields.id]
        oldOfferId = task[fields.oldOffer]

        if method=='C': #CREATE ACTION
            rc = self.argela.addPackageToSubscriber(subscriberid,serviceid,newOfferid)
            mstr = "CREATE"
        elif  method=='D': #DELETE ACTION
            rc = self.argela.removePackageFromSubscriber(subscriberid,serviceid)
            mstr = "DELETE"
        elif method=='S': #SET ACTION
            if newOfferid=="9001":
                #suspend subscriber dont care old packet
                rc= self.argela.suspendPackageSubscription(subscriberid,serviceid)
                mstr = "SUSPEND"
            elif oldOfferId=="9001":
                #resume subscriber dont care new  packet
                rc= self.argela.resumePackageSubscription(subscriberid,serviceid)
                mstr = "RESUME"
            elif newOfferid is None and oldOfferId is not None:
                #delete the old package
                mstr = "SET_DELETE_OLD"
                rc = self.argela.removePackageFromSubscriber(subscriberid,serviceid)
            elif newOfferid is None and oldOfferId is None:
                #ambiguous action! No offers
                #skip it with jobstatus code=7
                self.updateTask(paketid,7,None,None,None)
            elif newOfferid is not None:
                #set subscriber
                mstr = "PKT CHANGE"
                rc= self.argela.packageChange(subscriberid,serviceid,newOfferid)

        if rc[0] == 200 and rc[1]==0 and rc[2]==1:
            self.updateTask(paketid,3,rc[1],rc[3],rc[4])
            pass
        else:
            self.updateTask(paketid,6,rc[1],rc[3],rc[4])
            #unsuccessfull
            debugLogger.warning("Argela NEGATIVE RESP for: M: %s PID:%d, SUB:%s, GO:%s, NO:%s, OO:%s, RETURN_CODE:%d, RETURN_TEXT:%s" % (mstr,
            paketid,subscriberid,serviceid,newOfferid,oldOfferId,rc[1], rc[6]))


    def updateTask(self,paketid, jobStatus, arglaResponseCode, arglaResponseTime, arglaResponseDuration):
        if arglaResponseCode is None and arglaResponseTime is None and arglaResponseDuration is None:
             queryStr="UPDATE %s.%s SET jobstatus=%d WHERE id = %d"  %  (Config.dbName,Config.dbTableName, jobStatus,  paketid)
        else:
            queryStr="UPDATE  %s.%s SET jobstatus=%d, argelaResponseCode=%d, argelaRequestTime='%s', argelaResponseDuration=%f WHERE id = %d"  %  (
        Config.dbName,Config.dbTableName,jobStatus, arglaResponseCode, arglaResponseTime.strftime("%Y-%m-%d %H:%M:%S"), arglaResponseDuration , paketid)
##        debugLogger.debug("Query:" + queryStr)
        try:
            cursor = self.db.cursor()
            cursor.execute(queryStr)
        except:
            logger.error("Mysql update exception:%s" % queryStr)
        self.db.commit()


class fields():
    id=0
    request_time=1
    soapaction=2
    responseCode=3
    subscriberId=4
    goAccountId=5
    newOffer=6
    oldOffer=7
    jobStatus=8
    argelaResponseCode=9
    argelaRequestTime=10
    argelaResponseDuration=11

class ArglaFeedBacker():
    def __init__(self):
        self.workerThreadCount = Config.arglThreadCount

        logger.warn("App started to initialize")
        self.noThreads = Config.arglThreadCount
        self.workerQueues = []
        self.workerThreads = []
        self.batchBucketSize = Config.batchBucketSize

##Create Queues and Threads
        for i in range(self.noThreads):
            q = Queue.Queue()
            self.workerQueues.append(q)
            t = Worker(i+1,q)
            self.workerThreads.append(t)
##            t.run()

        self.stopApplication = False

    def connect2DB(self,reconnect=True):
        if reconnect:
            logger.warn("Mysql connection is closed. Try to reconnect..")
        return MySQLdb.connect(Config.dbServer, Config.dbUser, Config.dbPass, Config.dbName)

    def getTotalWaiting(self):
        waiting = 0
        for q in self.workerQueues:
            waiting += q.qsize()
        return waiting

    def run(self):
        global stopThread
        logger.info("Application running...")
        self.db = self.connect2DB()
        logger.info("Connected to Mysql")
        for th in self.workerThreads:
            th.start()
        while (not self.stopApplication):
##      	? Get 1000 rows that has jobstatus=0 order by paketid
            queryStr = "Select * from %s.%s where jobstatus=0 order by id limit %d" % (Config.dbName,Config.dbTableName, self.batchBucketSize)
            debugLogger.debug("Query:" + queryStr)
            cursor = self.db.cursor()
            allrows = []
            if cursor.execute(queryStr):
##                allrows = list(cursor)
##                allrows =  list(cursor.fetchall())
                for r in cursor:
                    allrows.append(list(r))
            else:
                logger.error("Query Error")
##    		? Batch_row_count = row.count()
            batch_row_count = len(allrows)
            logger.info("Found %d rows" % batch_row_count)
            if (batch_row_count==0):
                sleep(60)
                continue
            all_paket_ids = []
            all_subscribers = []
            for row in allrows:
                all_paket_ids.append(str(row[fields.id]))
##    		? Create Subscriber_Array
                if not row[fields.subscriberId] in all_subscribers:
                    all_subscribers.append(row[fields.subscriberId])
##    		? Update 1000 rows, SET jobstatus=1
            self.updateRows(all_paket_ids,1)
 ##    		? Select Gohesapno form Subscriber_Array
            all_subscribers_str = ",".join([ "'%s'" % s for s in  all_subscribers])
            selectGoHesapQueryStr = "select subscriberid,goaccountid from gohesapno where subscriberid in (%s)" % all_subscribers_str
            debugLogger.debug("Query:" + selectGoHesapQueryStr)
            goHesapNos = {}
            cursor = self.db.cursor()
            if cursor.execute(selectGoHesapQueryStr):
                for row2 in cursor:
                    goHesapNos[row2[0]] = row2[1]
##    		? Update rows_in_memory which has no gohesapno
            index = 0
            gofound = 0
            gonotfound = 0
            gonotfoundPackets = []
            for row3 in allrows:
                if row3[fields.goAccountId] is None:
                    if row3[fields.subscriberId] in goHesapNos:
                        allrows[index][fields.goAccountId] = goHesapNos[row3[fields.subscriberId]]
                        gofound += 1

                    else:
##                      go hesap no bulunamadi.
                        debugLogger.debug("GO hesap no is not found for %s,\nRow Information: %s" % (row3[fields.subscriberId], row3) )
                        gonotfound += 1
                        gonotfoundPackets.append(str(row3[fields.id]) )
                        #we may delete records that has no GO account id
##                        allrows.pop(index)
                        pass
                index += 1
##    		? Batch_start_time=now()
            logger.info("For %d rows found %d rows and not found %d rows" % (batch_row_count,gofound,gonotfound))
            #update rows with status_code= 5
            if len(gonotfoundPackets) > 0:
                self.updateRows(gonotfoundPackets,5)
            batchStartTime = datetime.now()
##    		? Dispatch rows to queues on modulus like:
            logger.info("Started sending all the Batch")
            #START PROCESSING RECORDS
            for row in allrows:
##    			? Queue[subscriber mod numofthreads].put(row)
                #SubscriberId should be numeric!!!
                try:
                    qid = int(row[fields.subscriberId]) % self.noThreads
                    if row[fields.goAccountId] is not None:
                        self.workerQueues[qid].put(row)
                except ValueError as e:
                    debugLogger.warn("Found invalid subscribername as:%s", row[fields.subscriberId])
                #mark row with errorcode=8
                    self.updateRows([row[fields.id]],8)

                    continue

##    		? Sleep(60)
            logger.info("Finished sending all the Batch")
##            sleep(60)
##    		? Check the total_bekleyen
##    		? While bekleyen > 100:
##    			? Sleep(10)
            k = self.getTotalWaiting()
            while ( k > self.batchBucketSize/10):
                logger.info("Waiting for workers to finish their jobs. Total waiting jobs:%d",k)
                sleep(60)
                k = self.getTotalWaiting()
##    		? Batch_process_duration = now() - Batch_start_time
            batchDuration = datetime.now() - batchStartTime
##    		? Check the total_bekleyen
##    		? Total_processed = Batch_row_count - total_bekleyen
            totalProcessed = batch_row_count - self.getTotalWaiting()
##    		? Report batch_status
            debugLogger.info("%d transaction finished at %.2f seconds. Average Speed: %.2f transaction per hour" % (totalProcessed, batchDuration.total_seconds(),
             batch_row_count/ batchDuration.total_seconds() * 3600.0  ) )
##    		? Report overall Status
            break

        while self.getTotalWaiting()>0:
            logger.info("Waiting for jobs to finish")
            sleep(2.0)
        stopThread = True
        sleep(2.0)

        logger.warning("Application Main loop is stopped")

    def updateRows(self,paketids, status):
        queryStr="UPDATE %s.%s SET jobstatus=%d WHERE id in (%s)" % (Config.dbName,Config.dbTableName,status,",".join(paketids))
        debugLogger.debug("Query:" + queryStr)
        cursor = self.db.cursor()
        cursor.execute(queryStr)
        self.db.commit()

def main():
    argla = ArglaFeedBacker()
    argla.run()


if __name__ == '__main__':
    main()
