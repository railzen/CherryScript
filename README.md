# Cherry一键脚本工具

## 介绍
Cherry一键脚本工具是一个轻量化的一键脚本工具，对于一些常见功能进行集成，可以避免记忆冗杂的命令、文件位置等。建议搭配UFW防火墙使用。

## 使用方法
### Debian / Ubuntu 安装依赖工具
```bash
apt install curl wget sudo net-tools ufw
```

***
### 一键脚本
```bash
curl -sSL https://ba.sh/ludo -o ludo.sh && bash ludo.sh
```
or
```bash
if [ -f /usr/bin/curl ];then curl -sSO https://raw.githubusercontent.com/railzen/CherryScript/main/ludo.sh;else wget -O ludo.sh https://raw.githubusercontent.com/railzen/CherryScript/main/ludo.sh;fi;chmod +x ludo.sh;./ludo.sh
```
***
### Cherry一键脚本 的支持列表：
- Debian
- Ubuntu
- CentOS 由于已经停止支持，现在从支持列表移除
***