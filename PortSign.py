#!/usr/bin/python3
# -*- coding:utf-8 -*-
import sys
import socket
import optparse
import threading
import queue

# 端口扫描类，继承threading.Thread
class PortScaner(threading.Thread):
    def __init__(self, portqueue, ip, timeout=3):# 需要传入端口队列、目标IP，探测超时时间
        threading.Thread.__init__(self)
        self._portqueue = portqueue
        self._ip = ip
        self._timeout = timeout
    def run(self):
        while True:# 判断端口队列是否为空
            if self._portqueue.empty():
                # 端口队列为空，说明已经扫描完毕，跳出循环
                break
                # 从端口队列中取出端口，超时时间为1s
            port = self._portqueue.get(timeout=0.5)
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self._timeout)
                result_code = s.connect_ex((self._ip, port))
# sys.stdout.write("[%d]Scan\n" % port)
# 若端口开放，则会返回0
                if result_code == 0:
                    sys.stdout.write("[%d] OPEN\n" % port)
            except Exception as e:
                print(e)
            finally:
                s.close()

def StartScan(targetip, port, threadNum):
# 端口列表
    portList = []
    portNumb = port
# 判断是单个端口还是范围端口
    if '-' in port:
       for i in range(int(port.split('-')[0]), int(port.split('-')[1])+1):
           portList.append(i)
    else:
       portList.append(int(port))
# 目标IP地址
    ip = targetip
# 线程列表
    threads = []
# 线程数量
    threadNumber = threadNum
# 端口队列
    portQueue = queue.Queue()
# 生成端口，加入端口队列
    for port in portList:
        portQueue.put(port)
    for t in range(threadNumber):
        threads.append(PortScaner(portQueue, ip, timeout=3))
# 启动线程
    for thread in threads:
        thread.start()
# 阻塞线程
    for thread in threads:
        thread.join()

if __name__ == '__main__':
    parser = optparse.OptionParser('Example: python %prog -i 127.0.0.1 -p80 \n python %prog -i 127.0.0.1 -p 1-100\n')
# 目标IP参数-i
    parser.add_option('-i', '--ip', dest='targetIP',default='127.0.0.1', type='string',help='target IP')
# 添加端口参数-p
    parser.add_option('-p', '--port', dest='port', default='80', type='string',help='scann port')
# 线程数量参数-t
    parser.add_option('-t', '--thread', dest='threadNum', default=100, type='int', help='scann thread number')
    (options, args) = parser.parse_args()
StartScan(options.targetIP, options.port, options.threadNum)