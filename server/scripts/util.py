
import xml.etree.cElementTree as ET
import time

def xml_get(xmltext:str, element:str):
    xml_tree = ET.fromstring(xmltext)
    return xml_tree.find(element).text

# 时间戳转时间
def timeStampToDatetime(timeStamp:str)->str:
    timeArray = time.localtime(float(timeStamp))
    datetime = time.strftime("%Y-%m-%d %H:%M:%S", timeArray)
    return datetime
