import argparse         # 命令行库
import binascii         # 二进制ASCII码
import socket           # TCP/IP库
import sys              # 系统库
import threading        # 线程库
import urllib.parse     # URL库
import json             # JSON库
import time             # 时间库
import hashlib          # 哈希计算库
import struct           # 数据结构库


#   双SHA256计算
#   输入、输出是b'\x'的byte类型
def sha256d(message):
    return hashlib.sha256(hashlib.sha256(message).digest()).digest()


#   byte大小端转换
#   输入是16进制str类型，输出是b'\x'的byte类型
#   例如：'12345678' -> b'\x78\x56\x34\x12'
def swap_endian_word(hex_word):
    #   将16进制字符串类型转为b'\x'的byte类型
    message = binascii.unhexlify(hex_word)

    #   判断是否是4字节的word
    if len(message) != 4:
        raise ValueError('必须是4字节的word！')

    #   大小端转换，byte的排列顺序颠倒
    return message[::-1]


#   word中byte的大小端转换，返回的是b'\x'的byte类型
#   输入是16进制str类型，输出是b'\x'的byte类型
#   例如：'1122334455667788' -> b'\x44\x33\x22\x11\x88\x77\x66\x55'
def swap_endian_words(hex_words):
    #   将16进制字符串类型转为b'\x'的byte类型
    message = binascii.unhexlify(hex_words)

    #   判断word中的字节数是否是4的整数倍
    if len(message) % 4 != 0:
        raise ValueError('必须是4字节对齐的word！')

    #   以4个byte为一个word，大小端转换
    tmp = b''
    for i in range(0, len(message) // 4):
        tmp = tmp + message[4 * i: 4 * i + 4][::-1]
    return tmp


#   人类可读的hash速率
def human_readable_hashrate(hashrate):
    #   换算成 hashes/s
    if hashrate < 1000:
        return '%2f h/s' % hashrate
    if hashrate < 1000000:
        return '%2f Kh/s' % (hashrate / 1000)
    if hashrate < 1000000000:
        return '%2f Mh/s' % (hashrate / 1000000)
    return '%2f Gh/s' % (hashrate / 1000000000)


#   Job类
class Job(object):
    #   Job初始化函数
    def __init__(self, job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime, target, extranounce1, extranounce2_size):
        #   来自mining.notify命令的参数
        self._job_id = job_id
        self._prevhash = prevhash
        self._coinb1 = coinb1
        self._coinb2 = coinb2
        self._merkle_branches = [b for b in merkle_branches]
        self._version = version
        self._nbits = nbits
        self._ntime = ntime

        #   来自mining.subsribe命令的参数
        self._target = target
        self._extranounce1 = extranounce1
        self._extranounce2_size = extranounce2_size

        #   只是挖矿作业是否停止的标志
        self._done = False

        #   用于计算Hash指标的参数
        self._dt = 0.0
        self._hash_count = 0

    #   停止挖矿作业
    def stop(self):
        self._done = True

    #   Hash速率，后续为了方便调用，将该方法装饰成属性
    @property
    def hashrate(self):
        #   如果当前停止了挖矿作业则返回0
        if self._dt == 0:
            return 0.0

        #   否则计算并返回Hash速率，单位时间内Hash计算个数
        # print(self._hash_count)
        # print(self._dt)
        return self._hash_count / self._dt

    #   计算二进制默克尔根
    def merkle_root_bin(self, extranounce2_bin):
        #   构造coinbase_bin(b'\x'的byte类型)信息，{coinb1(16进制str类型)， extranounce1(16进制str类型)， extranounce2_bin(b'\x'的byte类型) ， coinb2(16进制str类型)}
        #   binascii.unhexlify()是把16进制str类型转换为b'\x'的byte类型，所以'68'转换为b'\x68'
        coinbase_bin = binascii.unhexlify(self._coinb1) + binascii.unhexlify(self._extranounce1) + extranounce2_bin + binascii.unhexlify(self._coinb2)
        coinbase_hash_bin = sha256d(coinbase_bin)

        #   coinbase与merkle_branch（交易列表）两两配对成512bit数据，计算双sha256，得到默克尔根(b'\x'的byte类型)
        merkle_root = coinbase_hash_bin
        for branch in self._merkle_branches:
            merkle_root = sha256d(merkle_root + binascii.unhexlify(branch))
        return merkle_root

    #   挖矿，整个挖矿的计算过程
    #   nounce_start，nounce的起始值
    #   nounce_stride，nounce的步进值，方便在多线程中使用
    def mining(self, nounce_start=0, nounce_stride=1):
        #   获取当前时间
        t0 = time.time()

        #   遍历extranounce2的挖矿空间
        for extranounce2 in range(1, 0xffffffff):
            #   将extranounce2以无符号整形分成字节端元，并大端排列，'>I'是无符号整形大端排列的意思
            #   extranounce2是挖矿空间，所以无所谓大小端排列，都是可以的。在提交结果时也无需对extranounce2做大小端转换
            #   例如extranounce2(int类型)=1，那么extranounce2_bin(b'\x'的byte类型)=b'\x00\x00\x00\x01'
            extranounce2_bin = struct.pack('>I', extranounce2)

            #   计算默克尔根，b'\x'的byte类型
            #   例如，如果ascii没有对应就会用原数表示，b'~A\xa0\t\xe0\xca\xe4**\xee\x00&\xd0\x95ou\xa0]\x9c\xe2\xbaY1\xd1\xca\x812\x8bO\xb6s\xc4'
            merkle_root_bin = self.merkle_root_bin(extranounce2_bin)

            #   构建区块头，b'\x'的byte类型，{version, prevhash, merkle_root_bin, ntime, nbits}
            #   注意，从矿池得到的这几个数据是需要进行大小端转换的
            header_prefix_bin = swap_endian_word(self._version) + swap_endian_words(self._prevhash) + merkle_root_bin + swap_endian_word(self._ntime) + swap_endian_word(self._nbits)

            #   遍历nounce的挖矿空间，计算并验证工作证明
            for nounce in range(nounce_start, 0xffffffff, nounce_stride):
                #   如果工作被停止
                if self._done:
                    self._dt += (time.time() - t0)
                    raise StopIteration()

                #   将nounce以无符号整形分成字节端元，并小端排列，'<I'是无符号整形小端排列的意思
                #   nounce是挖矿空间，所以无所谓大小端排列，都是可以的。但在提交结果时需对nounce做大小端转换
                #   例如nounce(int类型)=1，那么nounce_bin(b'\x'的byte类型)=b'\x01\x00\x00\x00'
                #   得到的word_proof需要大小端转换byte顺序颠倒，才和self._target大小端一致
                nounce_bin = struct.pack('<I', nounce)
                work_proof = sha256d(header_prefix_bin + nounce_bin)[::-1].hex()
                # print(work_proof)

                #   hash计数加一
                self._hash_count += 1

                #   判断是否满足矿池下发的目标
                if work_proof <= self._target:
                    result = dict(
                        job_id=self._job_id,
                        extranounce2=extranounce2_bin.hex(),
                        ntime=self._ntime,
                        nounce=nounce_bin[::-1].hex()
                    )

                    #   目前先理解为打印结果，但实际与print函数不同
                    # print('目标是：', self._target)
                    # print('结果是：', work_proof)
                    yield result

                    # 计算时间差，并更新当前时间和hash计数
                    self._dt += (time.time() - t0)
                    t0 = time.time()
                    self._hash_count = 0


#   Subscription类
class Subscription(object):
    #   Subscription初始化函数
    def __init__(self):
        self._id = None                 #   订阅ID，str类型
        self._difficulty = None         #   难度，int类型
        self._extranounce1 = None       #   extranounce1，str类型
        self._extranounce2_size = None  #   extranounce2字节个数，int类型
        self._target = None             #  难度计算出的目标值，str类型
        self._worker_name = None
        self._mining_thread = None

    #   Subscription异常类，用于后续操作错误时，手动抛出异常
    class SubscriptionException(Exception):
        pass

    #   设定订阅参数
    def set_subscription(self, subscription_id_tmp, extranounce1_tmp, extranounce2_size_tmp):
        #   判断是否已经订阅，即已经得到矿池返回的ID号
        if self._id is not None:
            raise self.SubscriptionException('已经得到矿池返回的订阅ID号！')

        self._id = subscription_id_tmp
        self._extranounce1 = extranounce1_tmp
        self._extranounce2_size = extranounce2_size_tmp

    #   设定矿工名字
    def set_worker_name(self, worker_name_tmp):
        #   判断是否已经有用户名，即已经使用用户名登录到矿池了
        if self._worker_name:
            raise self.SubscriptionException('已经使用用户名登录到矿池了！')

        self._worker_name = worker_name_tmp

    #   通过函数的方式，获得类中的私有属性，矿工名字
    def get_worker_name(self):
        return self._worker_name

    #   根据矿池给的针对本矿机的难度，计算本次挖矿的目标值
    #   difficlty是int型的，可以直接用于计算
    def set_target(self, difficulty):
        #   输入的难度不能是负数
        if difficulty < 0:
            raise self.SubscriptionException('输入的难度是负数！')

        #   计算本次挖矿的目标值
        #   目标（256bit）=创世块目标（0x1d00ffff） / difficulty
        #   源码中把计算出的目标值扩大了一点，这样就降低了挖矿的难度
        #   同时考虑了难度如果是0无法做除法的情况
        if difficulty == 0:
            target = 2 ** 256 - 1
        else:
            target = min(int((0xffff0000 * 2 ** (256 - 64) + 1) / difficulty - 1 + 0.5), 2 ** 256 - 1)

        #   将原本target的位宽定位256bit，高位补零，右对齐
        #   self._target是十六进制str类型，即target十六进制数直接表示
        self._target = '%064x' % target
        self._difficulty = difficulty

        #   打印当前难度
        print('当前难度为：', self._difficulty)

    #   创建挖矿作业
    def create_job(self, job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime):

        #   如果未与矿池连接，则挂起报错
        if self._id is None:
            raise self.SubscriptionException('还未完成订阅任务！')

        #   使用输入参数，实例化Job类，运行初始化函数
        return Job(
            job_id=job_id,
            prevhash=prevhash,
            coinb1=coinb1,
            coinb2=coinb2,
            merkle_branches=merkle_branches,
            version=version,
            nbits=nbits,
            ntime=ntime,
            target=self._target,
            extranounce1=self._extranounce1,
            extranounce2_size=self._extranounce2_size
        )


#   Client类
#   实现矿机的各种功能
class Client(object):
    #   Client类的初始化函数
    def __init__(self):
        self._socket = None
        self._lock = threading.RLock()
        self._rpc_thread = None
        self._message_id = 1
        self._requests = dict()

    #   Client异常类，用于后续操作错误时，手动抛出异常
    class ClientException(Exception):
        pass

    #   TCP/IP连接
    def connect(self, socket_tmp):
        #   如果已经存在_rpc_thread线程，则手动抛出异常
        if self._rpc_thread:
            raise self.ClientException('矿池已被连接！')

        #   将外部解析的socket传入Client类中，使后续函数可以调用
        self._socket = socket_tmp

        #   创建一个_rpc_thread线程，并开启
        #   这个线程执行的是“_handle_incoming_rpc函数”
        self._rpc_thread = threading.Thread(target=self._handle_incoming_rpc)
        self._rpc_thread.daemon = True
        self._rpc_thread.start()

    #   给矿池发送命令
    def send(self, method, params):
        #   如果没有网络连接，则手动抛出异常
        if not self._socket:
            raise self.ClientException('Not connected')

        #   创建了一个request字典
        request = dict(id=self._message_id, method=method, params=params)

        #   将request进行JSON格式转换
        #   socket.send发送的是byte型的数据，所以需要把str型的message进行转换
        #   转换的时候是将message中的字符串，按照ascii码转成对应的byte数据
        #   68656c6c6f20776f7264 -> b'68656c6c6f20776f7264' = b'\x36\x38\x36\x35\x36...'
        message = json.dumps(request)
        with self._lock:
            self._requests[self._message_id] = request
            self._message_id += 1
            self._socket.send((message + '\n').encode())

        #   打印发送信息 {"id": 1, "method": "mining.subscribe", "params": []}
        # print(message)

        #   返回发送的内容，方便后续处理矿池发回的消息
        return request

    #   _rpc_thread线程的运行函数
    #   用于处理矿池发回的数据
    def _handle_incoming_rpc(self):
        #   接收的数据
        data = ""

        while True:
            #   判断是否接受完成
            #   如果接受完成，则从'\n'分割，共分成2部分
            if '\n' in data:
                (line, data) = data.split('\n', 1)
            #   如果未接收完成，则从self._socket中继续接收，并将接收的数据拼接
            #   socket.recv接收的数据是byte型的，所以需要转成str型赋值给chunk
            #   转换的时候是将chunk的byte数据，按照ascii码转成对应的字符串
            #   b'68656c6c6f20776f7264' = b'\x36\x38\x36\x35\x36...' -> 68656c6c6f20776f7264
            else:
                chunk = self._socket.recv(1024)
                data += chunk.decode()
                continue

            #   解析JSON格式的数据，如果解析失败则打印消息
            try:
                reply = json.loads(line)
                # print(reply)
            except IOError:
                print('将TCP数据解析成JSON格式失败！')
                continue

            #   判断返回信息是否与请求信息对应，如果对应则处理返回信息
            try:
                request = None
                with self._lock:
                    # 如果返回的reply中还有请求时的id，则处理则使用handle_reply处理
                    if 'id' in reply and reply['id'] in self._requests:
                        request = self._requests[reply['id']]
                    self.handle_reply(request=request, reply=reply)
            except IOError:
                print("返回消息与请求消息内容不符！!")
                continue

    #   处理回复信息函数（会被Mining类中的handle_reply函数重构）
    #   因为父类无法调用子类的函数，所以在这里起到占位的作用，真正的函数会在子类中编写
    def handle_reply(self, request, reply):
        pass


#   Mining类，属于Client类的子类
#   实现挖矿的各种功能
class Mining(Client):
    #   Mining类的初始化函数
    def __init__(self, url, username, password):
        #   初始化父类Client
        Client.__init__(self)

        #   将输入进的参数赋值给实体self中对应的参数
        self._url = url                         #   矿池的URL
        self._username = username               #   用户名
        self._password = password               #   密码
        self._job = None                        #   挖矿任务
        self._accepted_shares = 0               #   提交结果被矿池接收的计数
        self._subscription = Subscription()     #   Subscription类实例化
        self._login = 0                         #   登录成功标志
        self._login_first_job = 0               #   登录成功后的第一个任务标志
        self._change_difficulty_first_job = 0   #   修改难度后的第一个任务标志

    #   在这个函数中循环挖矿
    def mining_forever(self):
        #   根据矿池的URL，解析出对应的IP地址和端口
        url = urllib.parse.urlparse(self._url)
        hostname = url.hostname
        port = url.port
        # print(hostname, port)

        #   创建用于TCP/IP通信的socket，并连接
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((hostname, port))
        self.connect(sock)

        #   发送挖矿作业请求
        self.send(method='mining.subscribe', params=[])

        #   一直循环挖矿
        while True:
            time.sleep(10)

    #   处理回复信息函数（重构了Client中handle_reply函数）
    #   因为父类无法调用子类的函数，所以真正的函数会在子类中编写
    #   根据返回信息中的方法，分别进行处理
    def handle_reply(self, request, reply):
        #   如果登录成功，下面的是因为矿池在返回信息的时候返回方法，可以从返回信息的方法中判断
        # if self._login == 1:

        #   返回信息的方法为'mining.set_difficulty'，则处理“改变难度，计算目标”
        if reply.get('method') == 'mining.set_difficulty':
            #   如果返回的信息结构不对，则挂起
            if 'params' not in reply or len(reply['params']) != 1:
                print('矿池回复的改变难度格式错误！')

            #   提取矿池返回的参数
            #   difficulty，int类型
            (difficulty,) = reply['params']

            #   根据难度值计算目标值，并将目标值给到Subscription类中
            self._subscription.set_target(difficulty)

            #   清空改变难度后第一个任务的标志
            self._change_difficulty_first_job = 0

            #   成功完成改变难度，计算目标
            print('成功完成改变难度，计算目标任务!')

        #   返回信息的方法为'mining.notify'，则处理“挖矿任务”
        elif reply.get('method') == 'mining.notify':
            #   如果返回的信息结构不对，则挂起
            if 'params' not in reply or len(reply['params']) != 9:
                print('矿池回复的挖矿任务格式错误！')

            #   提取矿池返回的参数
            #   job_id，str类型
            #   prevhash，str类型，256nit
            #   coinb1，str类型
            #   coinb2，str类型
            #   merkle_branches，list类型，每个单元是str类型
            #   version，str类型
            #   nbits，str类型
            #   ntime，str类型
            #   clean_jobs，bool类型
            (job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime, clean_jobs) = reply['params']

            #   只有在登录后的第一个任务，或者更改难度后的第一个任务，或者强制开始新的任务时，调用挖矿线程
            if self._login == 1 and self._login_first_job == 0:
                self.mining_job_thread(job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime)

                #   第一个任务或新任务标志，置位
                self._login_first_job = 1
                self._change_difficulty_first_job = 1

                #   登录后的第一个任务，开启挖矿线程
                print('登录后的第一个任务，开启挖矿线程!')

            elif self._login == 1 and self._change_difficulty_first_job == 0:
                self.mining_job_thread(job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime)

                #   第一个任务或新任务标志，置位
                self._login_first_job = 1
                self._change_difficulty_first_job = 1

                #   改变难度后的第一个任务，开启挖矿线程
                print('改变难度后的第一个任务，开启挖矿线程!')

            elif self._login == 1 and clean_jobs:
                self.mining_job_thread(job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime)

                #   第一个任务或新任务标志，置位
                self._login_first_job = 1
                self._change_difficulty_first_job = 1

                #   强制开始新的任务，开启挖矿线程
                print('强制开始新的任务，开启挖矿线程!')

        #   如果还未登录，下面的是因为矿池在返回信息的时候不返回方法，所以只能从发送请求的方法中判断
        elif request:
            #   请求信息的方法为'mining.subscribe'，则处理“订阅任务”
            if request.get('method') == 'mining.subscribe':
                #   如果返回的信息结构不对，则挂起
                if 'result' not in reply or len(reply['result']) != 3 or len(reply['result'][0]) != 2:
                    print('矿池回复的订阅任务格式错误！')

                #   提取矿池返回的参数
                #   mining_notify，list类型。一般为['mining.notify', '数字']，都是str类型
                #   subscription_id，list类型。一般为['mining.set_difficulty', '数字']，都是str类型
                #   extranounce1，str类型
                #   extranounce2_size，int类型
                ((mining_notify, mining_difficulty), extranounce1, extranounce2_size) = reply['result']

                #   将提取到的订阅参数给到Subscription类中
                self._subscription.set_subscription(mining_notify[1], extranounce1, extranounce2_size)

                #   成功完成订阅任务
                print('成功完成订阅任务!')

                #   发送“矿机登录”请求
                self.send(method='mining.authorize', params=[self._username, self._password])

            #   请求信息的方法为'mining.authorize'，则处理“账户登录”
            elif request.get('method') == 'mining.authorize':
                #   如果返回的信息结构错误，或者拒绝了账户登录，则挂起
                if 'result' not in reply or not reply['result']:
                    print('矿池拒绝了账户登录！')

                #   将用户名从请求信息中提取出来，因为在账户登录时，矿池不会返回用户名
                #   用户名，str类型
                worker_name = request['params'][0]

                #   将提取到的用户名参数给到Subscription类中
                self._subscription.set_worker_name(worker_name)

                #   登录成功，清空改变难度后第一个任务的标志
                self._login = 1
                self._login_first_job = 0

                #   成功完成账户登录任务
                print('成功完成账户登录任务!')

            #   请求信息的方法为'mining.submit'，则处理“提交结果”
            elif request.get('method') == 'mining.submit':
                #   如果返回的信息结构错误，或者拒绝了提交结果，则挂起
                if 'result' not in reply or not reply['result']:
                    print('矿池拒绝了提交结果！')
                    print(reply)

                else:
                    #   本次挖矿被接收的结果计数，加一
                    self._accepted_shares += 1
                    #   成功完成一次提交结果
                    print('成功完成一次提交结果! 本次挖矿共提交次数：', self._accepted_shares)

    #   挖矿作业线程函数，用于创建、控制挖矿作业线程的函数
    def mining_job_thread(self, job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime):

        #   如果之前有作业，则停止
        if self._job:
            self._job.stop()
            print('旧的作业已停止！')

        #   实例化Job类，把新任务所有需要的参数传入
        self._job = self._subscription.create_job(
            job_id=job_id,
            prevhash=prevhash,
            coinb1=coinb1,
            coinb2=coinb2,
            merkle_branches=merkle_branches,
            version=version,
            nbits=nbits,
            ntime=ntime
        )

        #   运行挖矿作业
        #   def中嵌套def，特殊用法，目前不去深究
        #   {'id': 3, 'method': 'mining.submit', 'params': ['2N16oE62ZjAPup985dFBQYAuy5zpDraH7Hk', 'a5d', b'00000001', '60a3cdf4', b'00b12acd']}
        def run(job):
            try:
                for result in job.mining():
                    params = [self._subscription.get_worker_name()] + [result[k] for k in ('job_id', 'extranounce2', 'ntime', 'nounce')]
                    self.send(method='mining.submit', params=params)
                    print("找到有效nounce: " + str(params))
                    print(human_readable_hashrate(job.hashrate))
            except IOError:
                print('提交结果时，发送错误！')

        #   开启挖矿作业线程，循环运行挖矿作业
        thread = threading.Thread(target=run, args=(self._job,))
        thread.daemon = True
        thread.start()


#   主函数
if __name__ == '__main__':
    #   创建一个命令行解析器
    #   description是对这个命令行解析器的描述
    parser = argparse.ArgumentParser(description="比特币矿机")

    #   添加命令行交互参数
    #   '-xx'是命令行的命令名称
    #   dest是执行这条输入参数命令后，这个参数的名字，在后续解析中会使用该名字
    #   default是输入参数的默认值
    #   help是对这条命令的文字说明
    parser.add_argument('-url', dest='url', default='', help='miner pool url(eg: stratum+tcp://foobar.com:3333)')  # 矿池URL
    parser.add_argument('-user', dest='username', default='', help='username for mining server')                   # 用户名
    parser.add_argument('-pass', dest='password', default='', help='password for mining server')                   # 密码

    #   解析命令行输入参数
    #   sys.argv[1:]是指将所用输入的命令都解析
    options = parser.parse_args(sys.argv[1:])
    print(options.url, options.username, options.password)

    #   判断输入的用户名和密码是否都输入了，有缺少则退出程序
    if (not options.username) or (not options.password):
        print('May not enter username or password. Please enter again.')
        sys.exit(1)

    #   如果输入了矿池的URL，则开始挖矿
    if options.url:
        mining = Mining(options.url, options.username, options.password)
        mining.mining_forever()
