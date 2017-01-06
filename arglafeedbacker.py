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

import logging
import logging.config

logging.config.fileConfig("logging.ini")
logging._srcfile=None
logging.logThreads = 0
logging.logProcesses = 1

class Worker(Thread):
    def __init__(self, thread_no, mainlogger):
        super(MDNTesterThread, self).__init__()
        self.name = "Worker-%d" % thread_no
        mainlogger.warn("%s has initialized", self.name)
        self.logger = logging.getLogger('DEBUGLOG')



class ArglaFeedBacker():
    def __init__(self):
        self.workerThreadCount = Config.arglThreadCount
        self.logger = logging.getLogger('VLOG')
        self.logger.warn("App started to initialize")
        self.noThreads = Config.arglThreadCount
        self.workerQueues = []
        self.workerThreads = []
        self.batchBucketSize = 250

##Create Queues and Threads
        for i in range(self.noThreads):
            self.workerQueues.append(Queue.Queue())
            self.workerThreads.append(Worker(i+1, self.logger))

        self.stopApplication = False

    def connect2DB(self,reconnect=True):
        if reconnect:
            self.logger.warn("Mysql connection is closed. Try to reconnect..")
        return MySQLdb.connect(Config.dbServer, Config.dbUser, Config.dbPass, Config.dbName)

    def run(self):
        self.logger.info("Application running...")
        self.db = self.connect2DB()
        self.logger.info("Connected to Mysql")
        while (not self.stopApplication):
##      	? Get 1000 rows that has jobstatus=0 order by paketid
            queryStr = "Select * from Biglogs.argelaya where jobstatus=0 order by id limit %d" % self.batchBucketSize
            cursor = self.db.cursor()
            if cursor.execute(queryStr):
                allrows = list(cursor)
            else:
                self.logger.error("Query Error")

##    		? Batch_row_count = row.count()
            batch_row_count = allrows.count()
            all_paket_ids = []
            all_subscribers = []
            for row in allrows:
                all_paket_ids.append(row["id"])
##    		? Create Subscriber_Array
                if not row["subscriberId"] in all_subscribers:
                    all_subscribers.append(row["subscriberId"])
##    		? Update 1000 rows, SET jobstatus=1
            all_paket_ids_str= ",".join(all_paket_ids)
            updateQueryStr = "UPDATE Biglogs.argelaya SET jobstatus=1 where id in (%s)" % all_paket_ids_str
            cursor = self.db.cursor()
            cursor.execute(updateQueryStr)
##    		? Select Gohesapno form Subscriber_Array
            all_subscribers_str = ",".join([ "'%s'" % s for s in  all_subscribers])
            selectGoHesapQueryStr = "select subscriberid,goaccountid from gohesapno where subscriberid in (%s)" % all_paket_ids_str
            goHesapNos = {}
            cursor = self.db.cursor()
            if cursor.execute(selectGoHesapQueryStr):
                for row2 in cursor:
                    goHesapNos[row2["subscriberid"]] = row2["goaccountid"]
##    		? Update rows_in_memory which has no gohesapno
            index = 0
            for row3 in allrows:
                if row["goAccountId"] is None:
                    if row3["subscriberId"] in goHesapNos:
                        allrows[index]["goAccountId"] = goHesapNos[row3["subscriberId"]]
                    else:
##                      go hesap no bulunamadi.
                        logger.error("GO hesap no is not found for %s,\nRow Information: %s" % row3["subscriberId"], row3 )
##                        allrows.pop(index)
                index += 1

##    		? Batch_start_time=now()
            batchStartTime = datetime.now()
##    		? Dispatch rows to queues on modulus like:

##    			? Queue[subscriber mod numofthreads].put(row)

##    		? Sleep(60)
##    		? Check the total_bekleyen
##    		? While bekleyen > 100:
##    			? Sleep(10)
##    		? Batch_process_duration = now() - Batch_start_time
##    		? Check the total_bekleyen
##    		? Total_processed = Batch_row_count - total_bekleyen
##    		? Report batch_status
##    		? Report overall Status





def main():
    argla = ArglaFeedBacker()


if __name__ == '__main__':
    main()
