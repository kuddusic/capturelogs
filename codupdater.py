#!/usr/bin/python
#-------------------------------------------------------------------------------
# Name:        COD updater
# Purpose:
#
# Author:      189873
#
# Created:     15.04.2015
# Copyright:   (c) 189873 2015
# Licence:     <your licence>
#-------------------------------------------------------------------------------
# connect2Oracle, connect2mysql,

import cx_Oracle
import MySQLdb
import os
import sys


def connect2Oracle():
    os.environ["NLS_LANG"] = "TURKISH_TURKEY"
    #os.environ["NLS_LANG"] = "AL32"
    #os.environ["ORACLE_HOME"] = "c:\oracle\product\11.2.0\client_1"
    dsnStr = cx_Oracle.makedsn("172.24.78.84", "1521", "mwrpr2")
    con=cx_Oracle.connect(user='KCIFTCIBASI', password='Ahamy@db2015',dsn=dsnStr)

    print con.version
    return  con

def connect2Mysql():
    db = MySQLdb.connect('localhost', 'vod', 'VOD1234log', 'vodlog' ) #, charset='utf8mb4' )

    if not db:
        print("Could not connect to DB\n")
        return 0
    return db

def main():
    codinfo=[]
    cod_query = "select cod_url, nvl(title, PROVIDER_ID || ' ' || PROVIDER_ASSET_ID) title ,content_class,to_char(axiomdeactivatetime,'YYYY-MM-DD HH24:MI:SS') from iptvmwc.cod  where iptvmwc.cod.axiomactivatetime > (sysdate - 1) order by  iptvmwc.cod.cod_url"
    ora = connect2Oracle()
    cur = ora.cursor()
    cur.execute(cod_query)
    for result in cur:
        codinfo.append(result)
        print str(result[1])

    cur.close()
    ora.close()
    print "Get %d rows from Oracle\n" % (len(codinfo),)
  #  print codinfo
   # exit(0)
    query_template='INSERT INTO vodlog.cod values("%s","%s","%s","%s")'
    my = connect2Mysql()
    if (not my):
        print "Exiting\n"
        exit(0)
    counter = 0
    errored = 0
    for row in codinfo:
        try:
            counter += 1
            cur2 = my.cursor()
            str2 = query_template % (row[0],row[1],row[2],row[3])
##            print str2
            cur2.execute(str2)
            my.commit()

        except MySQLdb.Error, e:
##            print str(e)
            errored +=1

    my.close()
    print "Rows inserted: ",counter-errored,"Duplicate found: ", errored,"\n"

if __name__ == '__main__':
    main()
