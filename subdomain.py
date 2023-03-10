#print("\033[31mhello pyhton\033[0m")
#这是输出彩色字体的代码 31是红色  32是绿色  33是黄色  34是蓝色  35是紫色 36是青色 37是灰色  38是默认
#0 默认  1 高亮  4  下划线  5 闪烁  7  反显  8不可见

#功能块1  DNS、IP查询
import socket #用来域名查询
from whois import whois
import re
import requests
import warnings

warnings.filterwarnings("ignore") #全局忽略warn信息

print("\033[33m          _____________               /——\          \033[0m")
print("\033[34m        /   ________  \_\   _______  //_\ \    _____   __ \033[0m")
print("\033[32m       |  //        \_/_/  //  ____ \ ___  \  |      \| ||\033[0m")
print("\033[31m       | | |      _____   | | /   \_//   \  \ |  ||\  \ ||       \033[0m")
print("\033[35m       |  \_\____/\_\_\_\ _\_\ \_ /_ —————   \|  || \  \||\033[0m" )
print("\033[33m        \_____________/_/ \_\_\/____\|     \__\__||  \__\| \033[0m")
print("\033[35m                    \__/\033[0m   \033[36m\_/\033[0m")
print("\n")
print("                [dns]        DNS查询域名解析ip")
print("                [whois]      whois查询网站信息")
print("                [subdomain]  子域名挖掘")
a = str(input("\n请选择要执行的查询命令: "))

def subdomain(url3):
    domainurl = "https://scan.javasec.cn/run.php"
    data = {"id":1}
    head = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh-CN,zh;q=0.9"}
    con = requests.post(url=domainurl, data=data, headers=head, verify=False).content.decode()
    con1 = re.findall(r'"(.*?)"', con)
    i = 0
    while len(con1[i])!=0:
        url2 = "https://scan.javasec.cn/run.php?url="+str(con1[i])+"."+str(url3)
        con2 = requests.get(url=url2, headers=head, verify=False).content.decode()
        i = i+1
        if(len(str(con2))>0):
            print("\033[32m[+]\033[0m\033[34m查找结果: \033[0m", str(con2))
    print("\033[32m[+]\033[0m\033[34m爆破结束!\033[0m")
    #print(len(con1))
if(a=="dns"):
    try:
        ip = str(input("\n请输入要查询的域名: "))
        if(len(ip)!=0):
            print("\n\033[32m[+]\033[0m\033[34m查询结果IP为: \033[0m", socket.gethostbyname(ip))
        else:
            print("\n\033[31m[+]\033[0m\033[37m未获取到域名地址!\033[0m")
    except:
        print("\n\033[31m[+]\033[0m\033[37m请输入正确的域名!\033[0m")
if(a=="whois"):
    try:
        url = str(input("\n请输入要查询的域名: "))
        if(len(url)!=0):
            print("\n\033[32m[+]\033[0m\033[34m查询whois信息为: \033[0m", whois(url))
        else:
            print("\n\033[31m[+]\033[0m\033[37m未获取到域名地址!\033[0m")
    except:
        print("\n\033[31m[+]\033[0m\033[37m请输入正确的域名!\033[0m")
if(a=="subdomain"):
    url3 = str(input("请输入要爆破的主域名: "))
    #print("\n\033[32m[+]\033[0m\033[34m查找结果:\033[0m")
    subdomain(url3)
else:
    print("[+]退出程序!")