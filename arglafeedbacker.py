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

    def run(self):
        logger.warn("%s is running", self.name)
        while(not stopThread):
            try:
                j = self.queue.get(timeout=1.0)
                debugLogger.debug(j)
                sleep(1)
                self.queue.task_done()
            except Queue.Empty:
                continue
        logger.warn("%s is stopped", self.name)

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
        self.batchBucketSize = 250

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
            queryStr = "Select * from Biglogs.argelaya where jobstatus=0 order by id limit %d" % self.batchBucketSize
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
            all_paket_ids = []
            all_subscribers = []
            for row in allrows:
                all_paket_ids.append(str(row[fields.id]))
##    		? Create Subscriber_Array
                if not row[fields.subscriberId] in all_subscribers:
                    all_subscribers.append(row[fields.subscriberId])
##    		? Update 1000 rows, SET jobstatus=1
            all_paket_ids_str= ",".join(all_paket_ids)
            updateQueryStr = "UPDATE Biglogs.argelaya SET jobstatus=1 where id in (%s)" % all_paket_ids_str
            debugLogger.debug("Query:" + updateQueryStr)
            cursor = self.db.cursor()
            cursor.execute(updateQueryStr)
            self.db.commit()
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
            for row3 in allrows:
                if row3[fields.goAccountId] is None:
                    if row3[fields.subscriberId] in goHesapNos:
                        allrows[index][fields.goAccountId] = goHesapNos[row3[fields.subscriberId]]
                        gofound += 1
                    else:
##                      go hesap no bulunamadi.
                        debugLogger.debug("GO hesap no is not found for %s,\nRow Information: %s" % (row3[fields.subscriberId], row3) )
                        gonotfound += 1
                        #we may delete records that has no GO account id
##                        allrows.pop(index)
                        pass
                index += 1
##    		? Batch_start_time=now()
            logger.info("For %d rows found %d rows and not found %d rows" % (batch_row_count,gofound,gonotfound))

            batchStartTime = datetime.now()
##    		? Dispatch rows to queues on modulus like:
            logger.info("Started sending all the Batch")
            for row in allrows:
##    			? Queue[subscriber mod numofthreads].put(row)
                #SubscriberId should be numeric!!!
                qid = int(row[fields.subscriberId]) % self.noThreads
                self.workerQueues[qid].put(row)
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
            logger.info("%d jobs finished at %.2f seconds. Average job duration: %.2f" % (totalProcessed, batchDuration.total_seconds(),
             batchDuration.total_seconds() / batch_row_count  ) )
##    		? Report overall Status
            break

        while self.getTotalWaiting()>0:
            logger.info("Waiting for jobs to finish")
            sleep(2.0)
        stopThread = True
        sleep(2.0)

        logger.warning("Application Main loop is stopped")


def main():
    argla = ArglaFeedBacker()
    argla.run()


if __name__ == '__main__':
    main()
