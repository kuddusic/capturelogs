#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      189873
#
# Created:     09.01.2017
# Copyright:   (c) 189873 2017
# Licence:     <your licence>
#-------------------------------------------------------------------------------
import xml.etree.ElementTree

def main():
    xmlresponse = """<?xml version="1.0" ?><S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/">
    <S:Body><ns2:querySubscriberResponse xmlns:ns2="http://wtvmtv.server.webservice.core.provisioningmanager.iptv.argela.com.tr/">
    <return><returnCode>0</returnCode><returnStatus>1</returnStatus><returnText>Operation Success</returnText><transactionId>1701090938217560130</transactionId>
<packageInfoList><accountServiceId>92170109201</accountServiceId><baseType>2</baseType><name>Go Web S\xc3\xbcper Postpaid Paket</name>
<offerId>10000084</offerId><packageName>Go Web S\xc3\xbcper Postpaid Paket</packageName><pckgId>3210</pckgId><serviceGroupIdList>2</serviceGroupIdList>
<statusId>1</statusId></packageInfoList><packageInfoList><accountServiceId>72170109201</accountServiceId><baseType>2</baseType>
<name>Go Smart S\xc3\xbcper Postpaid Pkt</name><offerId>10000104</offerId><packageName>Go Smart S\xc3\xbcper Postpaid Pkt</packageName><pckgId>1520</pckgId>
<serviceGroupIdList>6</serviceGroupIdList><statusId>1</statusId></packageInfoList><packageInfoList><accountServiceId>2170109201</accountServiceId><baseType>3</baseType>
<name>Tivibu GO S\xc3\x9cPER Postpaid Pkt</name><offerId>10000061</offerId><packageName>Tivibu GO S\xc3\x9cPER Postpaid Pkt</packageName><pckgId>5239</pckgId>
<serviceGroupIdList>4</serviceGroupIdList><serviceGroupIdList>6</serviceGroupIdList><serviceGroupIdList>2</serviceGroupIdList><statusId>1</statusId></packageInfoList>
<packageInfoList><accountServiceId>82170109201</accountServiceId><baseType>2</baseType><name>Go Mobil Postpaid Pkt</name><offerId>3000122</offerId>
<packageName>Go Mobil Postpaid Pkt</packageName><pckgId>6080</pckgId><serviceGroupIdList>4</serviceGroupIdList><statusId>1</statusId>
</packageInfoList><subscriberStatus>1</subscriberStatus></return></ns2:querySubscriberResponse></S:Body></S:Envelope>
"""
    e = xml.etree.ElementTree.fromstring(xmlresponse)
##    returnCodeElem= e.find('.//{http://wtvmtv.server.webservice.core.provisioningmanager.iptv.argela.com.tr/}querySubscriberResponse/return/returnCode')
    print e.find('.//returnCode').text
    print e.find('.//returnStatus').text
    print e.find('.//returnText').text





if __name__ == '__main__':
    main()
