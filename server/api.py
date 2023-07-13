from flask import Flask, request, make_response
import sys

from scripts.WXPuhser import NotPusher
from scripts.logger import logger
from scripts.util import xml_get

app = Flask(__name__)

app.config['JSON_AS_ASCII'] = False

@app.route('/receive', methods=['GET','POST'])
def receive_from_wx():
    # verifyUrl 
    if request.method == 'GET':
        msg_signature = request.args['msg_signature'] # 电子签名
        timestamp     = request.args['timestamp'] # 时间戳   
        nonce         = request.args['nonce'] # 随机数
        echostr       = request.args['echostr']  # 密文

        ret, sEchoStr = NotPusher.wxcpt.VerifyURL(msg_signature, timestamp, nonce, echostr)
        if ret != 0:
            logger.info( "ERR: VerifyURL ret: " + str(ret))
            sys.exit(1)
    
        return sEchoStr
    # receive
    elif request.method == 'POST':
        try:
            # 1. 接收用户发送的消息
            msg_signature = request.args['msg_signature'] # 电子签名
            timestamp     = request.args['timestamp'] # 时间戳   
            nonce         = request.args['nonce'] # 随机数
            data = request.get_data().decode('utf-8')
            # 2. 解密, 拿到content
            ret, content = NotPusher.wxcpt.DecryptMsg(data, msg_signature, timestamp, nonce)
            if ret != 0:
                logger.error(f'视图函数[receive_from_wx]解密用户发送的消息时, error{e}')
                return make_response(f'errcode:[{ret}] when DecryptMsg', 200)
            
            # 3. 回复用户的消息
            msgType = xml_get(content, 'MsgType')
            username = xml_get(content, 'FromUserName')
            if msgType == 'text':
                text =  xml_get(content, 'Content')
                logger.info(f'用户[{username}] 发送消息: {text}')
                resp_msg = f'你好, {username}, Not 已经收到了你的消息'
                return NotPusher.generate_response(username, 'text', resp_msg)
            elif msgType == 'image':
                picUrl = xml_get(content, 'PicUrl')
                logger.info(f'用户[{username}] 发送图片: {picUrl}')
                resp_imgId = xml_get(content, 'MediaId')
                return NotPusher.generate_response(username, 'image', resp_imgId)
            else:
                logger.info(f'用户[{username}] 发送[{msgType}]类型消息]')
                resp_msg =  f'你好, {username}, Not 目前只支持自动回复text和image消息, 非常之笨...'
                return NotPusher.generate_response(username, 'text', resp_msg) 
        except Exception as e:
            logger.error(f'视图函数[receive_from_wx]回复用户的消息时发生错误, error{e}')

@app.route('/send', methods=['POST'])
def send_to_wx():
    """api接口, 客户端带着json数据请求该接口
       服务端验证签名, 解密数据, 请求企业微信接口, 向企业微信应用推送消息, 返回给客户端resp

    Examples:
        [Agent]:
            >>> url = 'http://1.117.65.89:33/send' | 'https://notzjw.top/wxpusher/send'
            >>> data = {
                    'fromUser':   fromUser,
                    'toUser'    : toUser,
                    'encryptMsg': encryptMsg(AES加密),
                    'signature' : signature(SHA1签名),
                    'timestamp' : timestamp(时间戳),
                    'nonce' : nonce(随机数),
                }
            >>> resp = requests.post(url=url, headers=self.headers, json=data)

    """
    # 获取请求的json数据
    data = dict()
    if request.content_type == 'application/json':
        data = request.get_json()
    else:
        return make_response('Please send json data, content_type should be application/json', 400)# 400 表示客户端请求的语法错误
    try:
        encryptMsg = data['encryptMsg'] # 密文
        fromUser = data['fromUser'] # 消息发送者
        toUser  = data['toUser']# 发给哪个用户
        signature = data['signature'] # 电子签名
        timestamp = data['timestamp']
        nonce = data['nonce']
    except Exception as e:
        return make_response('''Your data format is wrong, Example data = {
                                                                        'toUser'    : toUser,
                                                                        'encryptMsg': encryptMsg(AES加密),
                                                                        'signature' : signature(SHA1签名),
                                                                        'timestamp' : timestamp(时间戳),
                                                                        'nonce' : nonce(随机数),
                                                                    } ''',
                                                                    400)
    # 验证签名
    try:
        if signature != NotPusher.getSHA1(encryptMsg, timestamp, nonce):
            return make_response('Your mother fxxk bitch, dont diturb me =_=', 401) # 401 要求身份验证
    except Exception as e:
        return make_response(f'Your Signature Algorithm is wrong, check it! error:[{e}] when verify signature', 400)
    
    # 解密数据
    try:
        msg = NotPusher.AES_Decrypt(encryptMsg)
    except Exception as e:
        return make_response(f'Your AES_Encrypt is wrong, check it! error:[{e}] when AES_Decrypt', 400)
    
    # 发送消息给企业微信
    try:
        msg = msg + f'\n[消息来源]: {fromUser}'
        if NotPusher.send_text(msg, fromUser, toUser):
            return f'[{fromUser}] success to send msg[ {msg} ] to user[ {toUser} ]'
        else:
            return f'[{fromUser}] failed to send msg[ {msg} ] to user[ {toUser} ]'
    except Exception as e:
        return f'Sorry! Server get error when post wechat, error:[{e}] '

@app.route('/ping', methods=['GET', 'POST'])
def test():
    return {
        'message': 'ping success !!!',
        'ip_addr': request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    }

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5555, debug=False)