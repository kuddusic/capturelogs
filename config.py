class Config():
    LOG_SEVERITY=5
    LOG_ENABLED=True
    dbUser="biglogger"
    dbPass="VOD1234log"
##    dbServer="localhost"
    dbServer="172.29.25.50"
    dbName="Biglogs"
    dbTableName="argelaya_baslangic"
    arglThreadCount=3
    arglLogFileName="arglfeedback.log"
    arglDetailLogFileName="argldetail.log"
    batchBucketSize = 100
    useStagingArgla=True
