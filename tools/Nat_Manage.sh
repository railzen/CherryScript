#!/bin/bash

# 默认配置（根据你的需求修改）
PUBLIC_IF="eno1"       # 公网接口名称
PRIVATE_NET="vmbr0"    # 内网网桥名称
IPTABLES_SAVE_CMD="netfilter-persistent save"  # 持久化保存命令

# 临时文件记录规则
RULES_FILE="/tmp/dnat_rules.txt"

install() {
    if [ $# -eq 0 ]; then
        echo "未提供软件包参数!"
        return 1
    fi

    for package in "$@"; do
        if ! command -v "$package" &>/dev/null; then
            if command -v dnf &>/dev/null; then
                dnf -y update && dnf install -y "$package"
            elif command -v yum &>/dev/null; then
                yum -y update && yum -y install "$package"
            elif command -v apt &>/dev/null; then
                apt update -y && apt install -y "$package"
            elif command -v apk &>/dev/null; then
                apk update && apk add "$package"
            else
                echo "未知的包管理器!"
                return 1
            fi
        fi
    done

    return 0
}

# 添加规则
add_rule() {
  read -p "请输入本机端口 (例如 80): " EXT_PORT
  read -p "请输入目标IP (例如 10.10.10.10): " DEST_IP
  read -p "请输入目标端口 (例如 80): " DEST_PORT

  # 校验输入格式
  if ! [[ $EXT_PORT =~ ^[0-9]+$ ]] || ! [[ $DEST_PORT =~ ^[0-9]+$ ]]; then
    echo "错误：端口必须是数字！"
    exit 1
  fi

  if ! [[ $DEST_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "错误：IP地址格式无效！"
    exit 1
  fi

	localIP=$(ip -o -4 addr list | grep -Ev '\s(docker|lo)' | awk '{print $4}' | cut -d/ -f1 | grep -Ev '(^127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$)|(^10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$)|(^172\.1[6-9]{1}[0-9]{0,1}\.[0-9]{1,3}\.[0-9]{1,3}$)|(^172\.2[0-9]{1}[0-9]{0,1}\.[0-9]{1,3}\.[0-9]{1,3}$)|(^172\.3[0-1]{1}[0-9]{0,1}\.[0-9]{1,3}\.[0-9]{1,3}$)|(^192\.168\.[0-9]{1,3}\.[0-9]{1,3}$)')
	if [ "${localIP}" = "" ]; then
			localIP=$(ip -o -4 addr list | grep -Ev '\s(docker|lo)' | awk '{print $4}' | cut -d/ -f1|head -n 1 )
	fi
  # 添加DNAT规则
  iptables -t nat -A PREROUTING -p tcp --dport $EXT_PORT -j DNAT --to $DEST_IP:$DEST_PORT
  iptables -t nat -A POSTROUTING -p tcp -d $DEST_IP --dport $DEST_PORT -j SNAT --to-source $localIP
  iptables -t nat -A PREROUTING -p udp --dport $EXT_PORT -j DNAT --to $DEST_IP:$DEST_PORT
  iptables -t nat -A POSTROUTING -p udp -d $DEST_IP --dport $DEST_PORT -j SNAT --to-source $localIP
  iptables -A FORWARD  -p tcp --dport $DEST_PORT -d $DEST_IP -j ACCEPT



  save_rules
  echo "规则已添加：公网端口 $EXT_PORT => $DEST_IP:$DEST_PORT"
  break_end
}

del_rule() {
  list_rules
  read -p "请输入要删除的规则编号: " RULE_NUM

  # 获取规则内容
  RULE=$(sed -n "${RULE_NUM}p" $RULES_FILE)
  if [ -z "$RULE" ]; then
    echo "错误：无效的规则编号！"
    exit 1
  fi

  # 解析规则参数
  EXT_PORT=$(echo "$RULE" | grep -oP 'dpt:\K\d+')
  DEST_IP_PORT=$(echo "$RULE" | grep -oP 'to:\K\S+')
  DEST_IP=${DEST_IP_PORT%:*}
  DEST_PORT=${DEST_IP_PORT#*:}

  # 删除规则
  #iptables -t nat -D PREROUTING -p tcp --dport $EXT_PORT -j DNAT --to $DEST_IP:$DEST_PORT
  iptables -D FORWARD  -p tcp --dport $DEST_PORT -d $DEST_IP -j ACCEPT
  iptables -t nat -D PREROUTING -p tcp --dport $EXT_PORT -j DNAT --to $DEST_IP:$DEST_PORT
  iptables -t nat -D POSTROUTING -p tcp -d $DEST_IP --dport $DEST_PORT -j SNAT --to-source $localIP
  iptables -t nat -D PREROUTING -p udp --dport $EXT_PORT -j DNAT --to $DEST_IP:$DEST_PORT
  iptables -t nat -D POSTROUTING -p udp -d $DEST_IP --dport $DEST_PORT -j SNAT --to-source $localIP

  save_rules
  echo "规则已删除：$RULE"
  break_end
}

# 列出所有规则
list_rules() {
  echo "当前DNAT规则列表："
  echo "----------------------------------------"
  iptables -t nat -L PREROUTING -n --line-number | grep DNAT | grep "dpt:" > $RULES_FILE
  cat $RULES_FILE | nl -v 1
  echo "----------------------------------------"
}

# 保存规则
save_rules() {
	if ! command -v netfilter-persistent &>/dev/null; then
		install iptables-persistent
	fi
  
	echo "正在保存规则..."
	eval $IPTABLES_SAVE_CMD
}

break_end() {
      echo -e "\033[0;32m操作完成\033[0m"
      echo "按任意键继续..."
      read -n 1 -s -r -p ""
      echo ""
      clear
      show_menu
}

# 交互式菜单
show_menu() {
  while true; do
    echo ""
    echo "=============================="
    echo "NAT 端口转发管理菜单 "
    echo "=============================="
    echo "1. 添加端口转发规则"
    echo "2. 删除端口转发规则"
    echo "3. 列出所有规则"
    echo "——————————————————————————————"
    echo "0. 退出"
    echo "=============================="
    read -p "请输入选项 [0-3]: " CHOICE

    case $CHOICE in
      1) add_rule ;;
      2) del_rule ;;
      3) list_rules ;;
      #4) save_rules ;;
      0) exit 0 ;;
      *) echo "无效选项！" ;;
    esac
  done
}

show_menu 