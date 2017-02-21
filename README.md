dnsforwarder
============

### 一个简单的 DNS 转发代理

**主要功能：**

1. 指定不同的域名使用不同的服务器、不同的协议（UDP、TCP）进行查询；
2. DNS 缓存及相关的控制（支持自定义 TTL）；
3. 屏蔽包含指定的 IP 的 DNS 数据包；
4. Hosts 功能（支持通配符、CName 指定、网络 Hosts）；
5. 屏蔽指定的域名查询请求（广告屏蔽？）；
6. 跨平台（Windows、Linux）；

此版本保留了大部分 5 版本的功能，习惯 5 版本的朋友们可以到“5”分支内获取。

[安装和部署](https://github.com/holmium/dnsforwarder/wiki/%E9%A6%96%E6%AC%A1%E4%BD%BF%E7%94%A8%E6%96%B9%E6%B3%95-%7C-Deployment)

### A simple DNS forwarder

**Main Fetures:**

1. Forwarding queries to particular domains (and their subdomains) to specified servers over a specified protocol (UDP or TCP);
2. DNS cache and its controls (including modifying TTL for different domains);
3. Ignoring DNS responses from upstream servers containing particular IPs;
4. Loading hosts from file (including the support for wildcards, CName redirections and remote hosts files);
5. Refusing queries to specified domains (for ads blocking?);
6. Cross-platform (Windows, Linux);

[Installation & Deployment](https://github.com/holmium/dnsforwarder/wiki/%E9%A6%96%E6%AC%A1%E4%BD%BF%E7%94%A8%E6%96%B9%E6%B3%95-%7C-Deployment#versions)

### License :
GPL v3

### Dependencies :

  For Linux:

    pthread;
    libcurl (optional);

  For Windows:

    None.

### Macros needed to be declared while compiling :

  For Linux:

    None.

  For Windows x86 (at least Windows XP)

    WIN32

  For Windows x86-64 (at least Windows Vista):

    WIN32
    WIN64
- - -
**Consider** donation?

Bitcoin address : 1KwWqEkxcMXprwn8aTtV4qhqt1ZkBYqzra

Thanks!
