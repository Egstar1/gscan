#!/usr/bin/python
# coding: utf-8
# author: egstar
# version v1.0
# 文档辅助信息
# \033[显示方式;前景;背景m...\033[0m
# 前景 30 黑 31 红 32 绿 33 黄 34 蓝 35 紫红 36 青蓝 37白色
# 背景 40 黑 41 红 42 绿 43 黄 44 蓝 45 紫红 46 青蓝 47 白
# 显示方式 0 默认 1 高亮 4 下划线 5 闪烁 7 反白 8 不可见

from scapy.all import *
import os
import re
# 功能块1
import socket  # 用来域名查询
import time
import warnings
from optparse import OptionParser
from random import randint
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from whois import whois
import requests
import urllib3
from argparse import ArgumentParser
import logging
import threading
import queue

logging.getLogger("scapy.runtime").setLevel(logging.ERROR) #设置告警级别，只有ERROR会报错

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
warnings.filterwarnings("ignore") #全局忽略warn信息
urllib3.disable_warnings() #设置全局忽略Connection告警
session = requests.session()  #设置全局获取session
session.kepp_alive = False
session.mount('http://', HTTPAdapter(max_retries=5))
mem = ['dns', 'whois', 'domain', 'mail', 'shell', 'scan', 'help', 'port', 'dir', 'poc', 'ser'] #功能名称的列表

def info():
    print("\033[33m          _____________               /——\          \033[0m")
    print("\033[34m        /   ________  \_\   _______  //_\ \    _____   __ \033[0m")
    print("\033[32m       |  //        \_/_/  //  ____ \ ___  \  |      \| ||\033[0m")
    print("\033[31m       | | |      _____   | | /   \_//   \  \ |  ||\  \ ||       \033[0m")
    print("\033[35m       |  \_\____/\_\_\_\ _\_\ \_ /_ —————   \|  || \  \||\033[0m")
    print("\033[33m        \_____________/_/ \_\_\/____\|     \__\__||  \__\| \033[0m")
    print("\033[35m                    \__/   \_/\033[0m")

def helper():
    print("\n\n   --help  [options]  command:\n")
    print("           [dns]        DNS查询域名解析ip")
    print("           [whois]      whois查询网站信息")
    print("           [domain]     子域名挖掘")
    print("           [mail]       邮箱收集")
    print("           [scan]       主机探活")
    print("           [port]       端口探测")
    print("           [dir]        目录扫描")
    print("           [poc]        漏洞扫描")
    print("           [ser]        服务识别")
    print("           [shell]      交互式shell")
    print("           [help]       帮助文档信息")
    print("           [exit]       退出")

def subdomain(url3):
    domainurl = "https://scan.javasec.cn/run.php"
    data = {"id":1}
    head = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Connection": "close"}
    head1 = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
        "Connection": "close"}
    con = requests.post(url=domainurl, data=data, headers=head, verify=False).content.decode()
    con1 = re.findall(r'"(.*?)"', con)
    i = 0
    while len(con1[i])!=0:
        url2 = "https://scan.javasec.cn/run.php?url="+str(con1[i])+"."+str(url3)
        con2 = requests.get(url=url2, headers=head, verify=False).content.decode() #子域名爆破结果
        #con_http = session.get(url=http, headers=head1, verify=False)
        i = i+1
        if(len(str(con2))>0):
            http = "http://"+str(con1[i])+"."+str(url3)
            try:
                con_http = session.get(url=http, headers=head1, verify=False, timeout=(3, 10))
                print("\033[32m[+]\033[0m\033[34m查找结果: \033[0m %-60s" % str(con2), "status: %5d" % con_http.status_code, "     content-length:%8d" % len(con_http.content.decode()))
            except Exception as e:
                print("\033[32m[+]\033[0m\033[34m查找结果: \033[0m %-60s" % str(con2), "status:     0      content-length:       0")
    print("\033[32m[+]\033[0m\033[34m爆破结束!\033[0m")
    #print(len(con1))

#查找邮箱的正则
def search_mail(html):
    email = re.findall(r'[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+', html, re.I)
    return email
#定义全局邮箱爬虫header，可以自定义referer头
def headers(referer):
    headers =  {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0',
                'Accept': '*/*',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip,deflate',
                'Referer': referer,
                'Connection': 'close'
                }
    return headers
#定义目录扫描的header
def dirhead():
    dirheader = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0',
               'Accept': '*/*',
               'Accept-Language': 'en-US,en;q=0.5',
               'Accept-Encoding': 'gzip,deflate',
               'Connection': 'close'
               }
    return dirheader
#使用bing引擎爬取邮箱
def bing(url, page, key_word):  #key_word是交给搜索引擎用来检索邮箱的关键词，mail是自己输入域名，page是你要搜索的页数
    referer =  "http://cn.bing.com/search?q=email+site%3abaidu.com&qs=n&sp=-1&pq=emailsite%3abaidu.com&first=1&FORM=PERE1"
    mail_con = requests.session()
    bing_url = "http://cn.bing.com/search?q=" + key_word + "+site%3a" + url +"&qs=n&sp=-1&pq=" + key_word + "site%3a" + url + "&first=" + str((page-1)*10) + "&FORM=PERE1"
    mail_con.get('http://cn.bing.com', headers=headers(referer))
    e_mail = mail_con.get(bing_url, stream=True, headers=headers(referer), timeout=10) #这个用来获取网页爬取内容
    emails = search_mail(e_mail.text)  #使用search_mail()函数正则之后获取邮箱
    return emails

def baidu_search(url,page,key_word):
    email_list = []
    emails = []
    referer = "https://www.baidu.com/s?wd=email+site%3Abaidu.com&pn=1"
    baidu_url = "https://www.baidu.com/s?wd=" + key_word + "+site%3A" + url + "&pn="+str((page-1)*10)
    conn = requests.session()
    conn.get(referer, headers=headers(referer))
    r = conn.get(baidu_url, headers=headers(referer))
    soup = BeautifulSoup(r.text, 'lxml')
    tagh3 = soup.find_all('h3')
    for h3 in tagh3:
        href = h3.find('a').get('href')
        try:
            r = requests.get(href, headers=headers(referer), timeout=8)
            emails = search_mail(r.text)
        except Exception as e:
            pass
        for email in emails:
            email_list.append(email)
    return email_list

def getmail(url, pages):
    email_num = []
    key_words = ['email', 'mail', 'mailbox', '邮件', '邮箱', 'postbox']
    for page in range(1,int(pages)+1):
        for key_word in key_words:
            bing_email = bing(url, page, key_word)
            baidu_email = baidu_search(url, page, key_word)
            sum = bing_email+baidu_email
            for mail in sum:
                if mail in email_num:
                    pass
                else:
                    print("\033[32m[+]\033[0mInfo: ", mail)
                    email_num.append(mail)
#利用icmp协议进行主机探活
def icmp_scan(ip):
    ip_id = randint(1, 65535)
    icmp_id = randint(1, 65535)
    icmp_seq = randint(1, 65535)
    packet = IP(dst=ip, ttl=64, id=ip_id)/ICMP(id=icmp_id, seq=icmp_seq)/b'rootkit'
    result = sr1(packet, timeout=1, verbose=False)
    if result:
        for rcv in result:
            scan_ip = rcv[IP].src
            print(scan_ip+'  -->  Host is up')
    else:
        print(ip+'  -->  Host is down')

def icmp_mec():
    print("\n\n Usage:  <rhost>\n         192.168.1.1\n         192.168.1.1-124") #帮助信息
    ip = input("\n请输入要扫描的ip地址: ")
    print("\n\033[32m[+]\033[0m开始扫描 ", ip)
    print(" ")
    if '-' in ip:  # 把-作为分隔符用来区分ip段
        for i in range(int(ip.split('-')[0].split('.')[3]), int(ip.split('-')[1]) + 1):
            icmp_scan(ip.split('.')[0] + '.' + ip.split('.')[1] + '.' + ip.split('.')[2] + '.' + str(i))
            time.sleep(0.2)
    else:
        icmp_scan(ip)
    print("\n\033[32m[+]\033[0m扫描结束 ")

#定义tcp扫描函数
def tcp_scan(ip):
    rport = random.randint(1, 65535)
    packet = IP(dst=ip)/TCP(flags="A", dport=rport)
    res = sr1(packet, timeout=1.0, verbose=0)
    if res:
        if int(res[TCP].flags) == 4:
            time.sleep(0.2)
            print(ip + ' ---> up')
        else:
            print(ip + ' ---> down')
    else:
        print(ip + ' ---> down')

#定义tcp扫描的主函数用于接收参数并规范化，然后调用tcp_scan()
def tcp_mec():
    print("\n\n Usage:  <rhost>\n         192.168.1.1\n         192.168.1.1-124")  # 帮助信息
    ip = input("\n请输入要扫描的ip地址: ")
    print("\n\033[32m[+]\033[0m开始扫描 ", ip)
    print(" ")
    if '-' in ip:  # 把-作为分隔符用来区分ip段
        for i in range(int(ip.split('-')[0].split('.')[3]), int(ip.split('-')[1]) + 1):
            tcp_scan(ip.split('.')[0] + '.' + ip.split('.')[1] + '.' + ip.split('.')[2] + '.' + str(i))
            time.sleep(0.2)
    else:
        tcp_scan(ip)
    print("\n\033[32m[+]\033[0m扫描结束 ")

#定义udp扫描函数
def udp_scan(ip):
    rport = random.randint(1, 65535)  # 选取随机端口
    packet = IP(dst=ip)/UDP(dport=rport)
    res = sr1(packet, timeout=1.0, verbose=0)
    if res:
        if int(res[IP].proto) == 1:
            time.sleep(0.2)
            print(ip + ' ---> up')
        else:
            print(ip + ' ---> down')
    else:
        print(ip + ' ---> down')
#定义udp扫描的主函数
def udp_mec():
    print("\n\n Usage:  <rhost>\n         192.168.1.1\n         192.168.1.1-124")  # 帮助信息
    ip = input("\n请输入要扫描的ip地址: ")
    print("\n\033[32m[+]\033[0m开始扫描 ", ip)
    print(" ")
    if '-' in ip:  # 把-作为分隔符用来区分ip段
        for i in range(int(ip.split('-')[0].split('.')[3]), int(ip.split('-')[1]) + 1):
            udp_scan(ip.split('.')[0] + '.' + ip.split('.')[1] + '.' + ip.split('.')[2] + '.' + str(i))
            time.sleep(0.2)
    else:
        udp_scan(ip)
    print("\n\033[32m[+]\033[0m扫描结束 ")

#端口扫描类，可以创建多个子线程提高扫描速度，需要三个参数ip,端口
class Portscan(threading.Thread):
    def __init__(self, portqueue, ip, timeout=3):
        threading.Thread.__init__(self)
        self._portqueue = portqueue
        self._ip = ip
        self._timeout = timeout
    def run(self):
        while True: #先判断有没有传入端口
            if self._portqueue.empty():
                break
            port = self._portqueue.get(timeout=1.0)
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self._timeout)
                res_code = s.connect_ex(self._ip, port)
                if res_code == 0:
                    sys.stdout.write("%d is OPEN" % port)
            except Exception as e:
                print(e)
            finally:
                s.close()
#开始端口扫描函数的编写
def Pscan(tip, port, threadNum): #定义默认值
    portlist = []  #用一个数组列表存放要扫描的端口
    p = port
    if '-' in p:
        for i in range(int(port.split('-')[0]), int(port.split('-')[1])+1):
            portlist.append(i)    #如果有-这个分隔符就把每个端口切割存入portlist
    else:
        portlist.append(int(port))
    ip = tip
    threads = []
    threadCount = threadNum #线程的数量
    portQueue = queue.Queue() #队列
    for ports in portlist:
        portQueue.put(ports)
    for t in range(threadCount):
        threads.append(Portscan(portQueue, ip, timeout=3))
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
#端口扫描的主函数，用来接收用户的参数输入
def StartPscan():
    print("\nUsage:   <ip>  <port>  <thread>")
    print("           127.0.0.1  80")
    print("           127.0.0.1  80  100")
    print("           127.0.0.1  1-65535  100")
    print("\n           默认端口80、默认线程为100")
    try:
        try:
            a, b, c = (input("\n请输入地址及端口: ").split())
            tip = str(a)
            port = str(b)
            thread = int(c)
            Pscan(tip, port, thread)
        except Exception as e:
            Pscan(tip="127.0.0.1", port="80", threadNum=100)
    except KeyboardInterrupt:
        take = str(input(("确认退出程序？(Y 退出/N 继续): ")))
        if(take == 'Y'):
            pass


def portinfo():
    print("\nUsage:   <option1> ip <option2> port <option3> thread")
    print("\n         -i 127.0.0.1  -p80  -t 100")
    print("\n         --ip 127.0.0.1  -port1-65535  --thread 100")

#定义目录扫描函数
def dirscan():
    url = input("\n\033[32m[+]\033[0m请输入url: ")
    print(" ")
    if url[-1] != '/':
        url = url+'/'
    dir = input('\033[32m[+]\033[0m请输入字典路径(默认为dir.txt): ')
    print(" ")
    print("\033[32m[+]\033[0m开始扫描: \n")
    url_list = []
    if dir == '':
        dir = "dir.txt"
    try:
        with open(dir, 'r') as f:
            for a in f:
                a = a.replace('\n', '')
                url_list.append(a)
            f.close()
    except:
        print("\033[31m[-]\033[0m"+dir+"文件不存在! ")
    for l in url_list:
        con = url+l
        try:
            res = requests.get(url=con, headers=dirhead(), allow_redirects=False, verify=False)
            if res.status_code == 200:
                print("\033[32m%-75s" % con, "status: %4d" % res.status_code, "     conten-length: %7d" % len(res.content.decode()), "\033[0m")
            if res.status_code == 301 or res.status_code == 302:
                url_cor = res.headers['location']
                if res.headers['location'] != '':
                    res_cor = requests.get(url=url_cor, headers=dirhead(), verify=False)
                    print("\033[36m%-75s" % con, "status: %4d" % res.status_code, "     conten-length: %7d" % len(res.content.decode()), "    ----->\033[0m")
                    if res_cor.status_code == 200:
                        print("\033[32m%-75s" % con, "\033[0m", "\033[32mstatus: %4d" % res_cor.status_code, "     conten-length: %7d" % len(res_cor.content.decode()), "\033[0m")
                    if res_cor.status_code == 401 or res.status_code == 403:
                        print("\033[31m%-75s" % con, "status: %4d" % res_cor.status_code, "     conten-length: %7d" % len(res_cor.content.decode()), "\033[0m")
                    if res_cor.status_code == 500 or res.status_code == 503 or res.status_code == 502:
                        print("\033[35m%-75s" % con, "status: %4d" % res_cor.status_code, "     conten-length: %7d" % len(res_cor.content.decode()), "\033[0m")
                if res.headers['location'] == '':
                    print("\033[36m%-75s" % con, "status: %4d" % res.status_code, "     conten-length: %7d" % len(res.content.decode()), '\033[0m')
            if res.status_code == 401 or res.status_code == 403:
                print("\033[31m%-75s" % con, "status: %4d" % res.status_code, "     conten-length: %7d" % len(res.content.decode()), "\033[0m")
            if res.status_code == 500 or res.status_code == 503 or res.status_code == 502:
                print("\033[35m%-75s" % con, "status: %4d" % res.status_code, "     conten-length: %7d" % len(res.content.decode()), "\033[0m")
        except:
            pass

#定义漏洞扫描的接口函数，可以外接漏扫
def poc():
    print("\nUsage:    <pocname>         <command>")
    print("\n          <sqli>            sql注入")
    print("          <cmdi>            命令注入")
    print("          <email>           邮箱收集")
    print("          <js>              收集js链接")
    sel = input(("\n\033[32m[+]\033[0m请输入漏扫模块: "))
    if sel == 'sqli':
        print("\nUsage:    <option>      <command>")
        print("          -u            指定扫描的url路径")
        print("          -r            指定扫描的url文件路径")
        print("          -p            指定注入参数")
        print("          --data        指定post注入参数")
        print("          --dbs         探测数据库")
        print("          -D            指定数据库(爆破数据库)")
        print("          -T --table    指定数据表(爆破数据表)")
        print("          -C --column   指定字段(爆破字段)")
        print("          --is-dba      判断是否dba用户")
        cmd = input(("\n\033[32m[+]\033[0m请输入指令: "))
        if len(str(cmd)) != 0:
            sql = 'python ./sqlmap/sqlmap.py '+str(cmd)
            query = os.system(sql)
            print("\n\033[32m[+]\033[0m扫描结束")
        if len(str(cmd)) == 0:
            print("\n\033[31m[-]\033[0m未获取到命令! ")
    if sel == 'email':
        print("\nUsage:    <option>      <command>")
        print("          <domain>      收集的域名")
        print("          <domains>     存放的域名文件")
        print("\n     ex:  baidu.com")
        print("          domain.txt")
        cmd = input(("\n\033[32m[+]\033[0m请输入域名或文件: "))
        if len(str(cmd)) != 0:
            if cmd[-4:] != '.txt':
                sql = 'py -3.9 ./emailall/emailall.py --domain '+str(cmd)+' run'
            if cmd[-4:] == '.txt':
                sql = 'py -3.9 ./emailall/emailall.py --domains ' + str(cmd) + ' run'
            query = os.system(sql)
            print("\n\033[32m[+]\033[0m收集结束! ")
        if len(str(cmd)) == 0:
            print("\n\033[31m[-]\033[0m未获取到命令! ")
    if sel == 'js':
        print("\nUsage:    <option>      <command>")
        print("          <url>      url地址")
        print("\n     ex:  http://baidu.com")
        cmd = input(("\n\033[32m[+]\033[0m请输入url地址: "))
        print("")
        if len(str(cmd)) != 0:
            sql = 'python JSFinder.py -u '+str(cmd)
            query = os.system(sql)
            print("\n\033[32m[+]\033[0m收集结束! ")
        if len(str(cmd)) == 0:
            print("\n\033[31m[-]\033[0m未获取到命令! ")
#指纹库
SIGN = (
    b'FTP|FTP|^220.*FTP',
    b'Telnet|Telnet|^\r\n%connection closed by remote host!\x00$',
    b'MySQL|MySQL|mysql_native_password',
    b'oracle-https|^220- ora',
    b'Telnet|Telnet|Telnet',
    b'VNC|VNC|^RFB',
    b'IMAP|IMAP|^\* OK.*?IMAP',
    b'POP|POP|^\+OK.*?',
    b'SMTP|SMTP|^554 SMTP',
    b'SSH|SSH|^SSH-',
    b'HTTPS|HTTPS|Location: https',
    b'HTTP|HTTP|HTTP/1.1',
    b'HTTP|HTTP|HTTP/1.0',
)
#对比指纹库来返回服务信息的函数
def banner(res, port):
    text = ''
    open = 'open'
    Unrecongnized = 'Unrecongnized'
    if re.search(b'<title>502 Bad Gateway', res):
        proto = {"服务连接失败! "}
    for pattern in SIGN:
        pattern = pattern.split(b'|')
        if re.search(pattern[-1], res, re.IGNORECASE):
            proto = "%-11s" % port+'%-11s' % open+'%-10s' % pattern[1].decode()
            break
        else:
            proto = "%-11s]" % port+'%-11s' % open+'%-10s' % Unrecongnized
    print(proto)
#服务识别的请求函数
def serv_re(ip, port):
    res = ''
    probe = 'GET / HTTP/1.0\r\n\r\n'
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    result = sock.connect_ex((ip, int(port)))
    if result == 0:
        try:
            sock.sendall(probe.encode())
            res = sock.recv(256)
            if res:
                banner(res, port)
        except(ConnectionResetError, socket.timeout):
            pass
    else:
        pass
    sock.close()
#服务识别函数的主函数
def serv():
    ip = input("\n\033[32m[+]\033[0m请输入IP信息: ")
    port = input("\n\033[32m[+]\033[0m请输入端口信息: ")
    print("\n\033[32m[+]\033[0m开始扫描 ", ip, "\n")
    print('{0:<10}'.format("PORT"), '{0:<10}'.format("STATUS"), '{0:<10}'.format("SERVICE"), "\n")
    for li in port.split(','):
        serv_re(ip ,li)
        time.sleep(0.2)
    print("\n\033[32m[+]\033[0m扫描结束! ")

info()
helper()
choice = str(input("\n\033[32m[+]\033[0m请输入命令: "))
while len(choice)!=0:
    if (choice == "dns"):
        try:
            ip = str(input("\n\033[32m[+]\033[0m请输入要查询的域名: "))
            if (len(ip) != 0):
                print("\n\033[32m[+]\033[0m\033[36m查询结果IP为\033[0m: ", socket.gethostbyname(ip))
            else:
                print("\n\033[31m[-]\033[0m\033[37m未获取到域名地址!\033[0m")
        except:
            print("\n\033[31m[+]\033[0m\033[37m请输入正确的域名!\033[0m")
    if (choice == "whois"):
        try:
            url = str(input("\n\033[32m[+]\033[0m请输入要查询的域名: "))
            if (len(url) != 0):
                print("\n\033[32m[+]\033[0m\033[36m查询whois信息为: \033[0m", whois(url))
            else:
                print("\n\033[31m[-]\033[0m\033[37m未获取到域名地址!\033[0m")
        except:
            print("\n\033[31m[+]\033[0m\033[37m请输入正确的域名!\033[0m")
    if (choice == "domain"):
        url3 = str(input("\n\033[32m[+]\033[0m请输入要爆破的主域名: "))
        # print("\n\033[32m[+]\033[0m\033[34m查找结果:\033[0m")
        subdomain(url3)
    if (choice == "mail"):
        url = str(input("\n\033[32m[+]\033[0m请输入要收集的邮箱域名: "))
        # print("\n\033[32m[+]\033[0m\033[34m查找结果:\033[0m")
        if len(url) != 0:
            pages = input("\n\033[32m[+]\033[0m请输入从搜索引擎上检索的页数: ")
            if pages:
                print("\n\033[32m[+]\033[0m\033[36m开始收集: \033[0m", url)
                pages = int(pages)
                getmail(url, pages)
                print("\n\033[32m[+]\033[0m\033[36m搜索结束: \033[0m")
            else:
                print("\n\033[32m[+]\033[0m\033[36m开始收集: \033[0m", url)
                pages = 10
                getmail(url, pages)
                print("\n\033[32m[+]\033[0m\033[36m搜索结束! \033[0m")
        if len(url) == 0:
            print("\n\033[31m[-]\033[0m\033[37m未获取到域名地址!\033[0m")
    if (choice == "scan"):
        print("\nUsage [option] ip: ")
        print("\n      [P] icmp扫描")
        print("\n      [T] TCP扫描")
        print("\n      [U] UDP扫描")
        l = ['P', 'p', 'T', 't', 'U', 'u']
        sel = str(input("\n\033[32m[+]\033[0m选择要使用的扫描模式: "))
        if sel == 'P' or sel == 'p':
            icmp_mec()
        if sel == 'T' or sel == 't':
            tcp_mec()
        if sel == 'U' or sel == 'u':
            udp_mec()
        if sel not in l:
            print("\n\033[31m[-]\033[0m暂未开发的扫描模式")
    if (choice == "port"):
        try:
            portinfo()
            sel = str(input("\n\033[32m[+]\033[0m请输入命令: "))
            getip = sel.split()
            print("\n")
            print(getip[1], " 开放端口: \n")
            out = "python PortSign.py " + sel
            show = os.system(out)
            print("\n\033[32m[+]\033[0m扫描结束")
        except KeyboardInterrupt:
            take = str(input(("\033[32m[+]\033[0m确认退出程序？(Y 退出/N 继续): ")))
            if (take == 'Y' or take == 'y'):
                pass
    if (choice == "dir"):
        dirscan()
        print("\n\033[32m[+]\033[0m扫描结束!")
    if (choice == "poc"):
        poc()
    if (choice == "ser"):
        serv()
    if (choice == "shell"):
        print("\n快捷指令:      ")
        print("           <start cmd>   windows当前路径下打开新窗口")
        print("           <chdir/pwd>   返回当前路径")
        print("           <dir/ls>      列出目录下文件")
        print("           <exit>        退出命令执行")
        b = str(input("\n\033[32m[+]\033[0m命令执行窗口: "))
        while len(b)!=0:
            if b != 'exit':
                print("")
                b = os.system(b)
                b = str(input("\n\033[32m[+]\033[0m命令执行窗口: "))
            else:
                break
    if (choice == "help"):
        helper()
    if (choice == "exit"):
        print("\n\033[32m[+]\033[0m退出程序!")
        break
    if choice not in mem:
        print("\n\033[33m[*]\033[0m功能还在开发中!")
    choice = str(input("\n\033[32m[+]\033[0m请输入命令: "))
#print("\n\033[32m[+]\033[0m退出程序!")