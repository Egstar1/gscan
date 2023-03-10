# gscan
An Information gathering tools.综合信息收集工具
# Readme

###### 1、介绍

** Gscan**是一款使用Python3基于web渗透测试开发的信息收集扫描器，其融合了大部分的信息收集能力于一体。如常见的主机探活、端口扫描、目录扫描、邮箱收集等，同时还提供接口用于拓展其漏洞扫描能力，对于python开发者来说，其作为一款开源工具可以自定义拓展功能。该工具借鉴了前辈们安全开发经验，让使用者在使用过程中简单、易懂、高效。

###### 2、安装Gscan

工具发布到github上，可以使用`git clone`下载到本地

```
git clone httpS://github.com/
```

###### 3、使用

需要先安装Gscan引用的python第三方库，全部集成到requirement.txt文件中，使用`pip`命令安装

```
pip install -r requirement.txt
```

启动方式如下

```
python3 Gscan.py
```

![image-20230311001318824](.\images\image-20230311001318824.png)

![image-20230311001318824](https://user-images.githubusercontent.com/71976870/224372177-befa9ebd-19bf-4688-9ac3-2085021a4c55.png)
