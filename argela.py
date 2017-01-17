#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      189873
#
# Created:     29.12.2016
# Copyright:   (c) 189873 2016
# Licence:     <your licence>
#-------------------------------------------------------------------------------
import xml.etree.ElementTree
import requests
from datetime import datetime,timedelta

class Argela():

    def __init__(self,staging=True,verbose=False):
        if staging:
            self.endpoint="172.20.31.128:8080" # staging QSDP
        else:
            self.endpoint="172.24.78.31:8080"
        self.provUrl = "http://"+ self.endpoint+"/ProvisioningWSWtvMtv/ProvisioningServerWtvMtv"
        self.verbose = verbose
        self.baseHeaders= {'Content-Type': 'text/xml;charset=UTF-8','Accept-Encoding': 'gzip,deflate','User-Agent': 'Apache-HttpClient/4.1.1 (java 1.5)',
            'Connection': 'Keep-Alive','SOAPAction': ''}
        self.xmlDebug=False
        self.responseDebug=False

    def callWebService(self,serviceMsg,serviceUrl=None ,soapAction="", actionDescription=""):
        if serviceUrl is None:
            serviceUrl = self.provUrl
        self.baseHeaders["SOAPAction"]=soapAction
        bodyMessage = """<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wtv="http://wtvmtv.server.webservice.core.provisioningmanager.iptv.argela.com.tr/">
   <soapenv:Header/>   <soapenv:Body>   %s   </soapenv:Body></soapenv:Envelope>"""   %  (serviceMsg,)

        if self.xmlDebug:
            print "--- REQUEST BEGIN ---\r\n"
            print bodyMessage
            print "--- REQUEST END ---\r\n"

        bodyMessage_ws_removed= ""
        for l in bodyMessage.splitlines():
            t = l.strip()
            if len(t)>0 and t[0]!="<":
                t = " " + t
            bodyMessage_ws_removed += t
        request_time = datetime.now()

        try:
            response = None
            response = requests.post(serviceUrl,data=bodyMessage_ws_removed,headers=self.baseHeaders)
        except requests.HTTPError as exc:
            httpStatusCode = response.status_code
        except Exception as exc:
            returnCode = -1
            returnStatus = -1
            reasonText = str(exc)
            response = None
            httpStatusCode = -1

        response_duration = datetime.now() - request_time

        if response is not None:
            if self.responseDebug:
                print "--- RESPONSE BEGIN ---\r\n"
                print response.content
                print "--- RESPONSE END ---\r\n"

            e = xml.etree.ElementTree.fromstring(response.content)
            returnCodeElem= e.find('.//returnCode')
            httpStatusCode = response.status_code


            if returnCodeElem is not None:
                returnCode = int(returnCodeElem.text)
                returnStatus = int(e.find('.//returnStatus').text)
                reasonText = e.find('.//returnText').text
    ##            print httpStatusCode, returnStatus, reasonText
            else:
                returnCode = httpStatusCode
                returnStatus = -1
                reasonText = response.reason

            if self.verbose:
                if httpStatusCode!= 200:
                    print soapAction,"'s RESPONSE FAILED: HTTP REASON CODE:",response.status_code,response.reason,"Argela returnCode:",returnCode,"retunStatus:",returnStatus
                else:
                    print soapAction,"'s RESPONSE OK"

            return  (httpStatusCode, returnCode, returnStatus, request_time, response_duration.total_seconds(), response.content,reasonText,soapAction)
        else: # response is None
            return  (httpStatusCode, returnCode, returnStatus, request_time, response_duration.total_seconds(), None,reasonText,soapAction)


    def getSubscriber(self,subscriberId,fullDetail=False):
        getSubscriberStr="""
      <wtv:querySubscriber>
       <subscriberId>%s</subscriberId>
      </wtv:querySubscriber>
        """ % (subscriberId,)

        rc = self.callWebService(getSubscriberStr,self.provUrl,soapAction="QuerySubscriber")
        if not fullDetail:
            return rc[1] #send only Content Text
        else:
            return rc

    def addPackageToSubscriber(self, subscriberId, serviceId, packageId):
        WSStr = """
         <wtv:addPackageToSubscriber>
         <subscriberId>%s</subscriberId>
         <accountServiceId>%s</accountServiceId>
         <packageID>%s</packageID>
      </wtv:addPackageToSubscriber>
        """ % (subscriberId, serviceId, packageId)
        return self.callWebService(WSStr,soapAction='AddPackage2Subscriber')

    def removePackageFromSubscriber(self, subscriberId, serviceId, reason=0):
        WSStr = """
      <wtv:removePackageFromSubscriber>
        <subscriberId>%s</subscriberId>
         <accountServiceId>%s</accountServiceId>
         <reason>%d</reason>
      </wtv:removePackageFromSubscriber>
        """ % (subscriberId, serviceId, reason)
        return self.callWebService(WSStr,soapAction='RemovePackageFromSubscriber')

    def packageChange(self, subscriberId, serviceId, newPackage):
        WSStr = """
      <wtv:packageChange>
         <!--Optional:-->
         <subscriberId>%s</subscriberId>
         <!--Optional:-->
         <accountServiceId>%s</accountServiceId>
         <!--Optional:-->
         <newPackageId>%s</newPackageId>
      </wtv:packageChange>
        """ % (subscriberId, serviceId, newPackage)
        return self.callWebService(WSStr,soapAction='packageChange')

    def suspendPackageSubscription(self, subscriberId, serviceId):
        WSStr = """
      <wtv:suspendPackageSubscription>
         <subscriberId>%s</subscriberId>
         <accountServiceId>%s</accountServiceId>
         <reason></reason>
      </wtv:suspendPackageSubscription>
        """ % (subscriberId, serviceId)
        return self.callWebService(WSStr,soapAction='suspendPackageSubscription')

    def resumePackageSubscription(self, subscriberId, serviceId):
        WSStr = """
      <wtv:resumePackageSubscription>
         <subscriberId>%s</subscriberId>
         <accountServiceId>%s</accountServiceId>
      </wtv:resumePackageSubscription>
        """ % (subscriberId, serviceId)
        return self.callWebService(WSStr,soapAction='resumePackageSubscription')


def main():
    a = Argela()
    print a.getSubscriber("testkudu2",True)
##    print a.addPackageToSubscriber("testkudu","2170109201",5239)
##    print a.addPackageToSubscriber("testkudu1","2170109202",5239)
##    print a.removePackageFromSubscriber("testkudu2","2170109203")



if __name__ == '__main__':
    main()
