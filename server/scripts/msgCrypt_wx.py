#!/usr/bin/env python
#-*- encoding:utf-8 -*-

""" 对企业微信发送给企业后台的消息加解密示例代码.
@copyright: Copyright (c) 1998-2014 Tencent Inc.

"""
# ------------------------------------------------------------------------

import base64
import string
import random
import hashlib
import struct
from Crypto.Cipher import AES
import xml.etree.cElementTree as ET                                                                                                                                                      
import socket

"""
关于Crypto.Cipher模块 ImportError: No module named 'Crypto'解决方案
请到官方网站 https://www.dlitz.net/software/pycrypto/ 下载pycrypto。
下载后 按照README中的“Installation”小节的提示进行pycrypto安装。
"""
WXBizMsgCrypt_OK = 0
WXBizMsgCrypt_ValidateSignature_Error = -40001
WXBizMsgCrypt_ParseXml_Error = -40002
WXBizMsgCrypt_ComputeSignature_Error = -40003
WXBizMsgCrypt_IllegalAesKey = -40004
WXBizMsgCrypt_ValidateCorpid_Error = -40005
WXBizMsgCrypt_EncryptAES_Error = -40006
WXBizMsgCrypt_DecryptAES_Error = -40007
WXBizMsgCrypt_IllegalBuffer = -40008
WXBizMsgCrypt_EncodeBase64_Error = -40009
WXBizMsgCrypt_DecodeBase64_Error = -40010
WXBizMsgCrypt_GenReturnXml_Error = -40011

class FormatException(Exception):
    pass

def throw_exception(message, exception_class=FormatException):
    """my define raise exception function"""
    raise exception_class(message)

class SHA1:
    """计算企业微信的消息签名接口"""   
    
    def getSHA1(self, token:str, timestamp:str, nonce:str, encrypt:str):
        """用SHA1算法生成安全签名
        @param token:  票据
        @param timestamp: 时间戳
        @param nonce: 随机字符串
        @param encrypt: 密文
        @return: 安全签名
        """
        try:
            sortlist = [token, timestamp, nonce, encrypt]
            sortlist.sort()
            sha = hashlib.sha1()
            sha.update("".join(sortlist).encode('utf-8'))
            return  WXBizMsgCrypt_OK, sha.hexdigest()
        except Exception as e:
            print(e)
            return  WXBizMsgCrypt_ComputeSignature_Error, None
  

class XMLParse:
    """提供提取消息格式中的密文及生成回复消息格式的接口"""   
    
    
    # xml被动响应包消息模板
    XML_RESPONSE_TEMPLATE = """
                        <xml>
                            <Encrypt><![CDATA[%(msg_encrypt)s]]></Encrypt>
                            <MsgSignature><![CDATA[%(msg_signaturet)s]]></MsgSignature>
                            <TimeStamp>%(timestamp)s</TimeStamp>
                            <Nonce><![CDATA[%(nonce)s]]></Nonce>
                        </xml>
                        """

    def extract(self, xmltext):
        """提取出xml数据包中的加密消息 
        @param xmltext: 待提取的xml字符串
        @return: 提取出的加密消息字符串
        """
        try:
            xml_tree = ET.fromstring(xmltext)
            encrypt  = xml_tree.find("Encrypt")
            print(encrypt.text)
            return  WXBizMsgCrypt_OK, encrypt.text
        except Exception as e:
            print(e)
            return  WXBizMsgCrypt_ParseXml_Error,None
    
    def generate_xmlResp(self, encrypt:str, signature:str, timestamp:str, nonce:str):
        """生成xml被动响应包消息

        Args:
            encrypt   (str): 加密后的消息密文
            signature (str): 安全签名
            timestamp (str): 时间戳
            nonce     (str): 随机字符串

        Returns:
            resp_xml (str): 被动响应包, 将该resp直接返回给企业微信, 实现自动回复功能
        """
        resp_info = {
                    'msg_encrypt' : encrypt,
                    'msg_signaturet': signature,
                    'timestamp'    : timestamp,
                    'nonce'        : nonce,
                     }
        resp_xml = self.XML_RESPONSE_TEMPLATE % resp_info
        return resp_xml   
    
    
 
class PKCS7Encoder():
    """提供基于PKCS7算法的加解密接口"""  
    
    block_size = 32
    def encode(self, text):
        """ 对需要加密的明文进行填充补位
        @param text: 需要进行填充补位操作的明文
        @return: 补齐明文字符串
        """
        text_length = len(text)
        # 计算需要填充的位数
        amount_to_pad = self.block_size - (text_length % self.block_size)
        if amount_to_pad == 0:
            amount_to_pad = self.block_size
        # 获得补位所用的字符
        pad = chr(amount_to_pad).encode('utf-8')
        return text + pad * amount_to_pad
    
    def decode(self, decrypted):
        """删除解密后明文的补位字符
        @param decrypted: 解密后的明文
        @return: 删除补位字符后的明文
        """
        pad = ord(decrypted[-1])
        if pad<1 or pad >32:
            pad = 0
        return decrypted[:-pad]
    
    
class Prpcrypt(object):
    """提供接收和推送给企业微信消息的加解密接口"""
    
    def __init__(self,key):

        #self.key = base64.b64decode(key+"=")
        self.key = key
        # 设置加解密模式为AES的CBC模式   
        self.mode = AES.MODE_CBC
    
            
    def encrypt(self, text:str, receiveid:str):
        """对明文进行加密
        @param text: 需要加密的明文
        @return: 加密得到的字符串
        """      
        # 16位随机字符串添加到明文开头
        text = self.get_random_str().encode('utf-8') +\
                struct.pack("I",socket.htonl(len(text.encode('utf-8')))) + \
                text.encode('utf-8') + \
                receiveid.encode('utf-8')
        # 使用PKCS7的填充方式对明文进行补位填充
        text = PKCS7Encoder().encode(text)
        
        try:
            cryptor = AES.new(self.key,self.mode,self.key[:16])
            # AES-CBC解密加密 -> bytes类型
            encryptedbytes = cryptor.encrypt(text)
            # 使用Base64进行编码 -> byte字符串
            encodestrs = base64.b64encode(encryptedbytes)
            #  对byte字符串按utf-8进行解码 -> str
            enctext = encodestrs.decode('utf8')
    
            return WXBizMsgCrypt_OK, enctext
        
        except Exception as e:
            print (e)
            return  WXBizMsgCrypt_EncryptAES_Error, None
    
    def decrypt(self, text:str, receiveid:str):
        """对解密后的明文进行补位删除
        @param text: 密文 
        @return: 删除填充补位后的明文
        """
        try:
            # utf-8编码 （str -> byte字符串）
            text = text.encode('utf-8') 
            # BASE64对密文进行解码 (byte字符串 -> bytes)
            encodebytes = base64.b64decode(text)
            # AES-CBC解密 (bytes -> byte字符串)
            cryptor = AES.new(self.key,self.mode,self.key[:16])
            plain_text  = cryptor.decrypt(encodebytes)
        except Exception as e:
            print(e) 
            return  WXBizMsgCrypt_DecryptAES_Error,None
        try:
            # 去掉补位字符串 + 去除16位随机字符串
            content = plain_text[16:-plain_text[-1]]
            xml_len = socket.ntohl(struct.unpack("I",content[ : 4])[0])
            msg = content[4 : xml_len+4].decode('utf-8')
            from_receiveid = content[xml_len+4:]
            from_receiveid = from_receiveid.decode('utf-8')
        except Exception as e:
            print(e)
            return  WXBizMsgCrypt_IllegalBuffer,None
        if  from_receiveid != receiveid:
            return WXBizMsgCrypt_ValidateCorpid_Error,None
        return 0, msg
    
    def get_random_str(self):
        """ 随机生成16位字符串
        @return: 16位字符串
        """ 
        rule = string.ascii_letters  + string.digits
        str1 = random.sample(rule, 16)
        return "".join(str1)
        
class WXBizMsgCrypt(object):
    #构造函数
    def __init__(self,sToken,sEncodingAESKey,sReceiveId):
        try:
            self.key = base64.b64decode(sEncodingAESKey+"=")  
            assert len(self.key) == 32
        except:
            throw_exception("[error]: EncodingAESKey unvalid !", FormatException) 
            # return WXBizMsgCrypt_IllegalAesKey,None
        self.m_sToken = sToken
        self.m_sReceiveId = sReceiveId

    def VerifyURL(self, sMsgSignature:str, sTimeStamp:str, sNonce:str, sEchoStr:str):
        """_summary_

        Args:
            sMsgSignature (str): 签名串,对应URL参数的msg_signature
            sTimeStamp    (str): 时间戳,对应URL参数的timestamp
            sNonce        (str): 随机串,对应URL参数的nonce
            sEchoStr      (str): 密文,  对应URL参数的echostr

        Returns:
            sReplyEchoStr:  解密之后的sEchoStr
        """
        ret, signature = SHA1().getSHA1(self.m_sToken, sTimeStamp, sNonce, sEchoStr)
        if ret  != 0:
            return ret, None 
        if not signature == sMsgSignature:
            return WXBizMsgCrypt_ValidateSignature_Error, None

        ret, sReplyEchoStr = Prpcrypt(self.key).decrypt(sEchoStr,self.m_sReceiveId)
        return ret,sReplyEchoStr
	
    def EncryptMsg(self, sReplyMsg:str, timestamp:str, sNonce:str):
        """将企业回复用户的消息加密打包

        Args:
            sReplyMsg (str): 企业号待回复用户的消息, xml格式的字符串
            sNonce    (str): 随机串,可以自己生成,也可以用URL参数的nonce
            timestamp (str): 时间戳,可以自己生成,也可以用URL参数的timestamp,如为None则自动用当前时间
            
        Returns:
            XMLencrypt:  加密后的可以直接回复用户的xml格式密文,包括msg_signature, timestamp, nonce, encrypt的xml格式的字符串,
        """
        # 明文 -> 密文
        ret, encrypt = Prpcrypt(self.key).encrypt(sReplyMsg, self.m_sReceiveId)
        if ret != 0:
            return ret, None
            
        # 生成安全签名 
        ret, signature = SHA1().getSHA1(self.m_sToken, timestamp, sNonce, encrypt)
        if ret != 0: 
            return ret, None
        # 生成xml格式的消息
        XMLencrypt = XMLParse().generate_xmlResp(encrypt, signature, timestamp, sNonce)
        return ret, XMLencrypt

    def DecryptMsg(self, sPostData:str, sMsgSignature:str, sTimeStamp:str, sNonce:str):
        """检验消息的真实性,并且获取解密后的明文
        
        Args: 
            sPostData     (str): 密文, POST请求的xml格式数据
            sMsgSignature (str): 签名串,对应URL参数的msg_signature
            sTimeStamp    (str): 时间戳,对应URL参数的timestamp
            sNonce        (str): 随机串,对应URL参数的nonce

        Returns:
            xml_content   (str):  解密后的原文
        """
        # 解析xml, 拿到密文
        xmlParse = XMLParse()
        ret, encrypt = xmlParse.extract(sPostData)
        if ret != 0:
            return ret, None
        
        # 验证签名
        ret, signature = SHA1().getSHA1(self.m_sToken, sTimeStamp, sNonce, encrypt)
        if not signature == sMsgSignature:
            return WXBizMsgCrypt_ValidateSignature_Error, None
        
        # 密文 -> 明文
        ret, xml_content = Prpcrypt(self.key).decrypt(encrypt,self.m_sReceiveId)
        if ret  != 0:
            return ret, None
        
        return ret, xml_content 

if __name__ == '__main__':
    
    sToken = 'dasdADWdawdaSDadada'
    sEncodingAESKey='6qkdMrq68nTKduznJYO1A37W2oEgpkMUvkttRToqhUt'
    corpid = 'wwa60e65009ddd160f'
    wxcpt = WXBizMsgCrypt(sToken, sEncodingAESKey, corpid)
    
    
    msg_signature = 'b88b8612766a7b9a291adbc6c0b6c8cfaa434faa' # 电子签名
    timestamp     = '1655123226' # 时间戳   
    nonce         = '5bx5kmawnwy' # 随机数

    msg = "notzjw"
    ret, cptMsg = wxcpt.EncryptMsg(msg, timestamp, nonce)
    print(cptMsg)
    
    sha1 = SHA1() 
    ret, signature = sha1.getSHA1(sToken, timestamp, nonce, msg)
    ret, Msg = wxcpt.DecryptMsg(cptMsg, signature, nonce , timestamp )
    print(Msg)