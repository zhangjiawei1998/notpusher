import hashlib
import random
import time
import base64
from Crypto.Cipher import AES
import requests

from .logger import logger
from .msgCrypt_wx import WXBizMsgCrypt


class WXPusher(object):
    # 文本消息模板, 即xml被动响应包加密前的内容模板
    TEXT_TEMPLATE =  """ 
                        <xml>
                            <ToUserName><![CDATA[%(toUser)s]]></ToUserName>
                            <FromUserName><![CDATA[%(fromUser)s]]></FromUserName> 
                            <CreateTime>%(createTime)s</CreateTime>
                            <MsgType><![CDATA[%(msgType)s]]></MsgType>
                            <Content><![CDATA[%(content)s]]></Content>
                        </xml>
                        """
    # 图片消息模板, 即xml被动响应包加密前的内容模板
    IMAGE_TEMPLATE =  """ 
                        <xml>
                            <ToUserName><![CDATA[%(toUser)s]]></ToUserName>
                            <FromUserName><![CDATA[%(fromUser)s]]></FromUserName> 
                            <CreateTime>%(createTime)s</CreateTime>
                            <MsgType><![CDATA[%(msgType)s]]></MsgType>
                            <Image>
                                <MediaId><![CDATA[%(media_id)s]]></MediaId>
                            </Image>
                        </xml>
                        """
    def __init__(self) -> None:
        # 企业id, 企业密钥 (用于获取企业token)
        self.corpid = 'wwa60e65009ddd160f'
        self.corpsecret = 'Dg5JcN1AwhABT8Mf9ygZ_EMm_lWZXCZ5zQMTrAsLsm8'
        # 访问权限, 2小时刷新一次
        self.access_token = 'k_GmHu7xe_lXJTAiW12UaPIqn6fGU5W9ASrWOBNxDEa56KabRR0t8DqhgxqUmWxbPKo0Zuptx8xK6OlL1pxLMQgS7jP-7YpryQAipUClOt2AzL8cEfdmxPF8orHe59MjFfPmEJrIChSjfyRgIs19cOpeK_lSY1A0AvFBveP9pLsilA6bD8U3ZwZvbAj6pIfmUviJzl0tIYxsKEfK4mbPrA'
        self.expires_in = -1
        
        # 应用id
        self.agentid = 1000002
        
        # 票据和密钥, 用于消息加密
        self.sToken = 'dasdADWdawdaSDadada'
        self.sEncodingAESKey='6qkdMrq68nTKduznJYO1A37W2oEgpkMUvkttRToqhUt'
        self.key = base64.b64decode(self.sEncodingAESKey+"=")
        assert len(self.key) == 32
        
        self.headers = {
            'User-Agent' :"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36"
        }
        # 用于消息加密解密
        self.wxcpt = WXBizMsgCrypt(self.sToken, self.sEncodingAESKey, self.corpid)
    
    def get_access_token(self):
        payload = {
            'corpid' : self.corpid,
            'corpsecret' : self.corpsecret
        } 
        url = 'https://qyapi.weixin.qq.com/cgi-bin/gettoken'

        resp_json = requests.get(url=url, params=payload).json()

        errcode, errmsg = self.resp_code(resp_json)
        if errcode == 0:
            self.access_token = resp_json['access_token']
            self.expires_in = resp_json['expires_in']
            logger.info(f'获取access_token成功')
        else:
            logger.info(f'获取access_token失败: errcode[{errcode}],errcode[{errmsg}]')
            
    def send_text(self, text:str, fromUser:str, toUser:str, party:str='@all', tag:str='@all', maxRetry:int=5):
        """推送消息给企业微信应用

        Args:
            text     (str): 文字消息
            fromUser (str): 发送者
            toUser   (str): 用户名
            party    (str): 部门. Defaults to '@all'.
            tag      (str): 标签. Defaults to '@all'.
            maxRetry (int): 最大尝试次数. Defaults to 5.

        Returns:
            (bool) :  是否发送成功
        """
        if maxRetry == -1: #达到最大尝试次数
            return False
 
        url = 'https://qyapi.weixin.qq.com/cgi-bin/message/send'
        payload = {
            'access_token' : self.access_token,
            'debug':1
        }
        data = {    
            'touser': toUser,
            'toparty':party,
            'totag':  tag,
            'msgtype': 'text',
            'agentid': self.agentid,
            'text':{
                'content': text
            },
            "safe":0,                        # 是否是保密消息，0表示可对外分享，1表示不能分享且内容显示水印
            "enable_id_trans": 0,            # 是否开启id转译，0表示否，1表示是，默认0。仅第三方应用需要用到，企业自建应用可以忽略。
            "enable_duplicate_check": 0,     # 是否开启重复消息检查，0表示否，1表示是，默认0
            "duplicate_check_interval": 1800 # 重复消息检查的时间间隔，默认1800s，最大不超过4小时
        }
        resp_json = requests.post(url=url, params=payload, json=data).json()
        errcode, errmsg = self.resp_code(resp_json)
        
        if errcode == 0:
            logger.info(f'[{fromUser}]向用户[{toUser}]发送消息成功, 消息:[{text}]')
            return True
        elif errcode in (42001, 40014): #access_token过期.错误 -> retry
            logger.info(f'token过期或者错误, 第{6-maxRetry}次尝试重新获取')
            self.get_access_token()
            logger.info(f'第{6-maxRetry}次尝试重新发送消息')
            ifsuccess = self.send_text(text, fromUser, toUser, party, tag, maxRetry-1)
            if not ifsuccess:
                logger.info(f'[{fromUser}]第{6-maxRetry}次尝试向用户[{toUser}]发送消息失败, errcode:[{errcode}], errmsg:[{errmsg}]')
            return ifsuccess
        else:
            logger.info(f'[{fromUser}]第{6-maxRetry}次尝试向用户[{toUser}]发送消息失败, errcode:[{errcode}], errmsg:[{errmsg}]')
            return False

    def resp_code(self, resp_json:dict):
        if ('errcode' in resp_json.keys()) and 'errmsg' in resp_json.keys():
            return resp_json['errcode'], resp_json['errmsg']
        else:
            return -1, 'no errmsg'
        
    def generate_response(self, username:str, msgType:str, msg:str):
        # 时间戳, 随机数
        timestamp = str(int(time.time()))
        nonce = ''.join([str(random.randint(0,9)) for _ in range(10)])

        # 生成消息->明文
        content = self.generate_content(username, self.corpid, timestamp, msgType, msg)
        
        # 加密消息->密文 and 生成被动响应包
        ret, xml_resp = self.wxcpt.EncryptMsg(content, timestamp, nonce)
        assert ret == 0, f'构造xml被动响应包时发生错误, 错误码:{ret}'

        return xml_resp
    
    def generate_content(self, username:str, fromUser:str, createTime:str, msgType:str, content:str):
        """  生成 消息content (明文)

        Args:
            username (str): 用户名
            fromUser (str): 企业id
            createTime (str): 消息创建时间
            msgType (str): 消息类型
            content (str): 消息内容(明文)

        Returns:
            content_xml (str): xml格式的消息
        """
        if msgType == 'text':
            text_info = {
                'toUser' : username,
                'fromUser' : fromUser,
                'createTime' : createTime,
                'msgType' : msgType,
                'content' : content,
            }
            return self.TEXT_TEMPLATE % text_info
        
        elif msgType == 'image':
            image_info = {
                'toUser' : username,
                'fromUser' : fromUser,
                'createTime' : createTime,
                'msgType' : msgType,
                'media_id' : content
            }
            return self.IMAGE_TEMPLATE % image_info
        
    
    def AES_Encrypt(self, data):
        vi = '0102030405060708'
        #  # 字符串补位, 补全data到16的倍数
        pad = lambda s: s + (16 - len(s) % 16) * chr(16 - len(s) % 16)
        data = pad(data)
       
        cipher = AES.new(self.key, AES.MODE_CBC, vi.encode('utf-8'))
        # 加密后得到的是bytes类型的数据
        encryptedbytes = cipher.encrypt(data.encode('utf-8'))
        # 使用Base64进行编码,返回bytestring
        encodestrs = base64.b64encode(encryptedbytes)
        #  对bytestring按utf-8进行解码
        enctext = encodestrs.decode('utf-8')

        return enctext

    def AES_Decrypt(self, data):
        vi = '0102030405060708'
        # utf-8编码  str -> bytestring
        data = data.encode('utf-8')
        # Base64解码 bytestring -> bytes
        encodebytes = base64.b64decode(data)
        # 密钥编码    bytes -> bytestring
        cipher = AES.new(self.key, AES.MODE_CBC, vi.encode('utf-8'))
        text_decrypted = cipher.decrypt(encodebytes)
        # 去掉末尾的补位字符 
        unpad = lambda s: s[0:-s[-1]]
        text_decrypted = unpad(text_decrypted)
        # utf-8解码 bytestring -> str 
        text_decrypted = text_decrypted.decode('utf-8')
        return text_decrypted
    
    def getSHA1(self, encrypt:str, timestamp:str, nonce:str):
        """用SHA1算法生成安全签名
        @param encrypt: 密文
        @param timestamp: 时间戳
        @param nonce: 随机字符串
        @return: 安全签名
        """
        try:
            sortlist = [self.sToken, timestamp, nonce, encrypt]
            sortlist.sort()
            sha = hashlib.sha1()
            sha.update("".join(sortlist).encode('utf-8'))
            return  sha.hexdigest()
        except Exception as e:
            logger.info(e)
            return  None

NotPusher = WXPusher()