#!/usr/bin/env bash
#cp -f ./ludo.sh ${work_path}/ludo.sh > /dev/null 2>&1

main_version="V1.1.23 Build250720"
work_path="/opt/CherryScript"
ssh_default_public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPleKQeroz6fG0LHfvYjjxN6L0zVztSfXbUogHs+jYrq"  #如果使用本脚本请把公钥改成自己的

main_menu_start() {
while true; do
clear
echo -e "${LightBlue}   _____ _    _ ______ _____  _______     __"
echo                "  / ____| |  | |  ____|  __ \|  __ \ \   / /"
echo                " | |    | |__| | |__  | |__) | |__) \ \_/ / "
echo                " | |    |  __  |  __| |  _  /|  _  / \   /  "
echo                " | |____| |  | | |____| | \ \| | \ \  | |   "
echo -e             "  \_____|_|  |_|______|_|  \_\_|  \_\ |_|   ${White}\n"

echo -e "${LightBlue}Cherry Script $main_version (Support for Ubuntu/Debian)${White}"
echo -e "${LightBlue}Personal use, unauthorized use prohibited!${White}"
echo -e "${LightBlue}------- Press ${DarkYellow}ludo${LightBlue} to start script -------${White}"
command -v ufw >/dev/null && ufw status | grep -q '^Status: active' && ssh_port=$(ss -tnlp | awk '/sshd/ && /LISTEN/ {gsub(".*:", "", $4); print $4; exit}') && ufw status | awk -v p="$ssh_port" '$2 == "ALLOW" && $1 ~ "(^|,|:|/)" p "(/tcp)?($|,|:)" {f=1} END {exit !f}' && echo -e "${DarkYellow}SSH Port $ssh_port Open${White}" || echo -e "${LightBlue}SSH Port $ssh_port Close${White}"

echo "------------------------"
echo "1. 系统信息查询"
echo "2. 系统更新"
echo "3. 系统清理"
echo "4. 常用工具 ▶"
echo "5. BBR管理 ▶"
echo "6. Docker管理 ▶ "
echo "7. 功能脚本合集 ▶ "
echo "8. 面板安装合集 ▶ "
echo "9. 端口转发工具 ▶ "
echo "10. 系统工具 ▶ "
echo "11. 安装Snell V4 ▶ "
echo "12. 安装Hysteria2 ▶ "
echo "13. SingBox脚本 ▶ "
echo "------------------------"
if [[ ${startup_check_new_version} == "true" ]]; then
    echo -e "99. 脚本更新 ${DarkYellow}● ${White}"
else
    echo "99. 脚本更新"
fi
echo "------------------------"
echo "0. 退出脚本"
echo "------------------------"
read -p "请输入你的选择: " choice

case $choice in
  edit)
      vi $work_path/config/start.sh
      clear
      exit 0
        ;;

  restart)
      ls /etc/systemd/system | grep Cherry- | xargs systemctl restart
      break_end
      exit 0
        ;;

  1)
    if true;then
        clear
        # 函数: 获取IPv4和IPv6地址
        ip_address

        if [ "$(uname -m)" == "x86_64" ]; then
          cpu_info=$(cat /proc/cpuinfo | grep 'model name' | uniq | sed -e 's/model name[[:space:]]*: //')
        else
          cpu_info=$(lscpu | grep 'BIOS Model name' | awk -F': ' '{print $2}' | sed 's/^[ \t]*//')
        fi

        if [ -f /etc/alpine-release ]; then
            # Alpine Linux 使用以下命令获取 CPU 使用率
            cpu_usage_percent=$(top -bn1 | grep '^CPU' | awk '{print " "$4}' | cut -c 1-2)
        else
            # 其他系统使用以下命令获取 CPU 使用率
            cpu_usage_percent=$(top -bn1 | grep "Cpu(s)" | awk '{print " "$2}')
        fi


        cpu_cores=$(nproc)

        mem_info=$(free -b | awk 'NR==2{printf "%.2f/%.2f MB (%.2f%%)", $3/1024/1024, $2/1024/1024, $3*100/$2}')

        disk_info=$(df -h | awk '$NF=="/"{printf "%s/%s (%s)", $3, $2, $5}')

        country=$(curl -s ipinfo.io/country)
        city=$(curl -s ipinfo.io/city)

        isp_info=$(curl -s ipinfo.io/org)

        cpu_arch=$(uname -m)

        hostname=$(hostname)

        kernel_version=$(uname -r)

        congestion_algorithm=$(sysctl -n net.ipv4.tcp_congestion_control)
        queue_algorithm=$(sysctl -n net.core.default_qdisc)

        # 尝试使用 lsb_release 获取系统信息
        os_info=$(lsb_release -ds 2>/dev/null)

        # 如果 lsb_release 命令失败，则尝试其他方法
        if [ -z "$os_info" ]; then
          # 检查常见的发行文件
          if [ -f "/etc/os-release" ]; then
            os_info=$(source /etc/os-release && echo "$PRETTY_NAME")
          elif [ -f "/etc/debian_version" ]; then
            os_info="Debian $(cat /etc/debian_version)"
          elif [ -f "/etc/redhat-release" ]; then
            os_info=$(cat /etc/redhat-release)
          else
            os_info="Unknown"
          fi
        fi

        output_status

        current_time=$(date "+%Y-%m-%d %I:%M %p")


        swap_used=$(free -m | awk 'NR==3{print $3}')
        swap_total=$(free -m | awk 'NR==3{print $2}')

        if [ "$swap_total" -eq 0 ]; then
            swap_percentage=0
        else
            swap_percentage=$((swap_used * 100 / swap_total))
        fi

        swap_info="${swap_used}MB/${swap_total}MB (${swap_percentage}%)"

        runtime=$(cat /proc/uptime | awk -F. '{run_days=int($1 / 86400);run_hours=int(($1 % 86400) / 3600);run_minutes=int(($1 % 3600) / 60); if (run_days > 0) printf("%d天 ", run_days); if (run_hours > 0) printf("%d时 ", run_hours); printf("%d分\n", run_minutes)}')

        echo ""
        echo "系统信息查询"
        echo "------------------------"
        echo "主机名: $hostname"
        echo "运营商: $isp_info"
        echo "------------------------"
        echo "系统版本: $os_info"
        echo "Linux版本: $kernel_version"
        echo -n "Linux内核版本: "
        cat /proc/version
        echo "------------------------"
        echo "CPU架构: $cpu_arch"
        echo "CPU型号: $cpu_info"
        echo "CPU核心数: $cpu_cores"
        echo "------------------------"
        echo "CPU占用: $cpu_usage_percent%"
        echo "物理内存: $mem_info"
        echo "虚拟内存: $swap_info"
        echo "硬盘占用: $disk_info"
        echo "------------------------"
        echo "$output"
        echo "------------------------"
        echo "网络拥堵算法: $congestion_algorithm $queue_algorithm"
        echo "------------------------"
        echo "公网IPv4地址: $ipv4_address"
        echo "公网IPv6地址: $ipv6_address"
        echo "------------------------"
        echo "地理位置: $country $city"
        echo "系统时间: $current_time"
        echo "------------------------"
        echo "系统运行时长: $runtime"
        echo
    fi
    ;;

  2)
    clear
    linux_update
    ;;

  3)
    clear
    linux_clean
    ;;

  4)
    while true; do
      clear
      echo "▶ 安装常用工具"
      echo "------------------------"
      echo "1. curl 下载工具"
      echo "2. wget 下载工具"
      echo "3. sudo 超级管理权限工具"
      echo "4. socat 通信连接工具 （申请域名证书必备）"
      echo "5. htop 系统监控工具"
      echo "6. iftop 网络流量监控工具"
      echo "7. unzip ZIP压缩解压工具"
      echo "8. tar GZ压缩解压工具"
      echo "9. tmux 多路后台运行工具"
      echo "10. ffmpeg 视频编码直播推流工具"
      echo "11. btop 现代化监控工具"
      echo "12. ranger 文件管理工具"
      echo "13. gdu 磁盘占用查看工具"
      echo "14. fzf 全局搜索工具"
      echo "15. frps 内网穿透工具"
      echo "16. gost 转发隧道工具"
      echo "17. ping 网络监测工具"
      echo "------------------------"
      echo "21. cmatrix 黑客帝国屏保"
      echo "22. sl 跑火车屏保"
      echo "------------------------"
      echo "31. 全部安装"
      echo "32. 全部卸载"
      echo "------------------------"
      echo "41. 安装指定工具"
      echo "42. 卸载指定工具"
      echo "------------------------"
      echo "0. 返回主菜单"
      echo "------------------------"
      read -p "请输入你的选择: " sub_choice

      case $sub_choice in
          1)
              clear
              install curl
              clear
              echo "工具已安装，使用方法如下："
              curl --help
              ;;
          2)
              clear
              install wget
              clear
              echo "工具已安装，使用方法如下："
              wget --help
              ;;
            3)
              clear
              install sudo
              clear
              echo "工具已安装，使用方法如下："
              sudo --help
              ;;
            4)
              clear
              install socat
              clear
              echo "工具已安装，使用方法如下："
              socat -h
              ;;
            5)
              clear
              install htop
              clear
              htop
              ;;
            6)
              clear
              install iftop
              clear
              iftop
              ;;
            7)
              clear
              install unzip
              clear
              echo "工具已安装，使用方法如下："
              unzip
              ;;
            8)
              clear
              install tar
              clear
              echo "工具已安装，使用方法如下："
              tar --help
              ;;
            9)
              clear
              install tmux
              clear
              echo "工具已安装，使用方法如下："
              tmux --help
              clear
              ;;
            10)
              install ffmpeg
              clear
              echo "工具已安装，使用方法如下："
              ffmpeg --help
              ;;

            11)
              clear
              install btop
              clear
              btop
              ;;
            12)
              clear
              install ranger
              cd /
              clear
              ranger
              cd ~
              ;;
            13)
              clear
              install gdu
              cd /
              clear
              gdu
              cd ~
              ;;
            14)
              clear
              install fzf
              cd /
              clear
              fzf
              cd ~
              ;;
            15)
                clear
                if [ ! -f "/etc/systemd/system/Cherry-frps.service" ];then
                    read -p "尚未安装FRPS服务，是否安装？[Y/n]" yn
                    if [[ ${yn} == [Yy] ]]; then
                        mkdir -p ${work_path}/frps && cd ${work_path}/frps
                        wget -q -nc --no-check-certificate https://raw.githubusercontent.com/railzen/CherryScript/main/tools/frps && chmod +x frps
                        wget -q -nc --no-check-certificate https://raw.githubusercontent.com/railzen/CherryScript/main/tools/frps.toml
                        mv -f frps.toml /opt/CherryScript/config/frps.toml
                        echo '
[Unit]
Description= Cherry-frps
After=network-online.target
Wants=network-online.target systemd-networkd-wait-online.service
[Service]
LimitNOFILE=32767 
Type=simple
User=root
Restart=on-failure
RestartSec=5s
ExecStartPre=/bin/sh -c 'ulimit -n 51200'
ExecStart=/opt/CherryScript/frps/frps -c /opt/CherryScript/config/frps.toml
[Install]
WantedBy=multi-user.target' > /etc/systemd/system/Cherry-frps.service
                        systemctl enable --now Cherry-frps
                        echo "服务已安装，可前往编辑[${work_path}/frps.toml]文件进行配置"
                    else
                        echo && echo "操作取消" && echo
                    fi	
                   
                else
                    read -p "当前已经安装FRPS服务，是否停止？[Y/n]" yn
                    if [[ ${yn} == [Yy] ]]; then
                        systemctl stop Cherry-frps
                        systemctl disable Cherry-frps
                        rm -f /etc/systemd/system/Cherry-frps.service
                    else
                        echo && echo "操作取消" && echo
                    fi
                fi
              ;;
             16)
              clear
              read -p "是否确认安装gost并同步安装开机自启服务？[Y/n]" yn
              [[ -z "${yn}" ]] && yn="y"
              if [[ ${yn} == [Yy] ]]; then
              # 安装最新版本 [https://github.com/go-gost/gost/releases](https://github.com/go-gost/gost/releases)
                bash <(curl -fsSL https://github.com/go-gost/gost/raw/master/install.sh) --install
                rm -rf ./*
                mkdir -p ${work_path}/config
                    if [ ! -f "${work_path}/config/start.sh" ];then
                        echo "#!/usr/bin/env bash" > ${work_path}/config/start.sh
                    fi
                    
                    chmod +x ${work_path}/config/start.sh
                    echo '
[Unit]
Description= Cherry-startup
After=network-online.target
Wants=network-online.target systemd-networkd-wait-online.service
[Service]
LimitNOFILE=32767 
Type=simple
User=root
Restart=on-failure
RestartSec=5s
ExecStartPre=/bin/sh -c 'ulimit -n 51200'
ExecStart=/opt/CherryScript/config/start.sh
[Install]
WantedBy=multi-user.target' > /etc/systemd/system/Cherry-startup.service
                    systemctl enable --now Cherry-startup
              else
                echo && echo "操作取消" && echo
              fi
              ;;
            17)
              clear
              install iputils-ping
              clear
              ping -V
              ;;

            21)
              clear
              install cmatrix
              clear
              cmatrix
              ;;
            22)
              clear
              install sl
              clear
              /usr/games/sl
              ;;

          31)
              clear
              install curl wget sudo socat htop iftop unzip tar tmux ffmpeg btop ranger gdu fzf vim
              ;;

          32)
              clear
              remove htop iftop unzip tmux ffmpeg btop ranger gdu fzf vim
              ;;

          41)
              clear
              read -p "请输入安装的工具名（wget curl sudo htop）: " installname
              install $installname
              ;;
          42)
              clear
              read -p "请输入卸载的工具名（htop ufw tmux cmatrix）: " removename
              remove $removename
              ;;

          0)
              back_main

              ;;

          *)
              echo "无效的输入!"
              ;;
      esac
      break_end
  done
    ;;

  5)
    if true; then
        clear
        if [ -f "/etc/alpine-release" ]; then
            while true; do
                  clear
                  congestion_algorithm=$(sysctl -n net.ipv4.tcp_congestion_control)
                  queue_algorithm=$(sysctl -n net.core.default_qdisc)
                  echo "当前TCP阻塞算法: $congestion_algorithm $queue_algorithm"

                  echo ""
                  echo "BBR管理"
                  echo "------------------------"
                  echo "1. 开启BBRv3              2. 关闭BBRv3（会重启）"
                  echo "------------------------"
                  echo "0. 返回上一级选单"
                  echo "------------------------"
                  read -p "请输入你的选择: " sub_choice

                  case $sub_choice in
                      1)
                        bbr_on

                          ;;
                      2)
                        sed -i '/net.core.default_qdisc=fq_pie/d' /etc/sysctl.conf
                        sed -i '/net.ipv4.tcp_congestion_control=bbr/d' /etc/sysctl.conf
                        sysctl -p
                        reboot
                          ;;
                      0)
                          break  # 跳出循环，退出菜单
                          ;;

                      *)
                          break  # 跳出循环，退出菜单
                          ;;

                  esac
            done
        else
            install wget
            wget --no-check-certificate -O tcpx.sh https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcpx.sh
            chmod +x tcpx.sh
            ./tcpx.sh
        fi
    fi
    ;;

  6)
    while true; do
      clear
      echo "▶ Docker管理器"
      echo "------------------------"
      echo "1. 安装更新Docker环境"
      echo "------------------------"
      echo "2. 查看Dcoker全局状态"
      echo "------------------------"
      echo "3. Dcoker容器管理 ▶"
      echo "4. Dcoker镜像管理 ▶"
      echo "5. Dcoker网络管理 ▶"
      echo "6. Dcoker卷管理 ▶"
      echo "------------------------"
      echo "7. 清理无用的docker容器和镜像网络数据卷"
      echo "------------------------"
      echo "20. 卸载Docker环境"
      echo "------------------------"
      echo "0. 返回主菜单"
      echo "------------------------"
      read -p "请输入你的选择: " sub_choice

      case $sub_choice in
          1)
            clear
            install_add_docker

              ;;
          2)
              clear
              echo "Dcoker版本"
              docker --version
              docker-compose --version
              echo ""
              echo "Dcoker镜像列表"
              docker image ls
              echo ""
              echo "Dcoker容器列表"
              docker ps -a
              echo ""
              echo "Dcoker卷列表"
              docker volume ls
              echo ""
              echo "Dcoker网络列表"
              docker network ls
              echo ""

              ;;
          3)
              while true; do
                  clear
                  echo "Docker容器列表"
                  docker ps -a
                  echo ""
                  echo "容器操作"
                  echo "------------------------"
                  echo "1. 创建新的容器"
                  echo "------------------------"
                  echo "2. 启动指定容器             6. 启动所有容器"
                  echo "3. 停止指定容器             7. 暂停所有容器"
                  echo "4. 删除指定容器             8. 删除所有容器"
                  echo "5. 重启指定容器             9. 重启所有容器"
                  echo "------------------------"
                  echo "11. 进入指定容器           12. 查看容器日志           13. 查看容器网络"
                  echo "------------------------"
                  echo "0. 返回上一级选单"
                  echo "------------------------"
                  read -p "请输入你的选择: " sub_choice

                  case $sub_choice in
                      1)
                          read -p "请输入创建命令: " dockername
                          $dockername
                          ;;

                      2)
                          read -p "请输入容器名: " dockername
                          docker start $dockername
                          ;;
                      3)
                          read -p "请输入容器名: " dockername
                          docker stop $dockername
                          ;;
                      4)
                          read -p "请输入容器名: " dockername
                          docker rm -f $dockername
                          ;;
                      5)
                          read -p "请输入容器名: " dockername
                          docker restart $dockername
                          ;;
                      6)
                          docker start $(docker ps -a -q)
                          ;;
                      7)
                          docker stop $(docker ps -q)
                          ;;
                      8)
                          read -p "$(echo -e "${Red}确定删除所有容器吗？(Y/N): ${White}")" choice
                          case "$choice" in
                            [Yy])
                              docker rm -f $(docker ps -a -q)
                              ;;
                            [Nn])
                              ;;
                            *)
                              echo "无效的选择，请输入 Y 或 N。"
                              ;;
                          esac
                          ;;
                      9)
                          docker restart $(docker ps -q)
                          ;;
                      11)
                          read -p "请输入容器名: " dockername
                          docker exec -it $dockername /bin/sh
                          break_end
                          ;;
                      12)
                          read -p "请输入容器名: " dockername
                          docker logs $dockername
                          break_end
                          ;;
                      13)
                          echo ""
                          container_ids=$(docker ps -q)

                          echo "------------------------------------------------------------"
                          printf "%-25s %-25s %-25s\n" "容器名称" "网络名称" "IP地址"

                          for container_id in $container_ids; do
                              container_info=$(docker inspect --format '{{ .Name }}{{ range $network, $config := .NetworkSettings.Networks }} {{ $network }} {{ $config.IPAddress }}{{ end }}' "$container_id")

                              container_name=$(echo "$container_info" | awk '{print $1}')
                              network_info=$(echo "$container_info" | cut -d' ' -f2-)

                              while IFS= read -r line; do
                                  network_name=$(echo "$line" | awk '{print $1}')
                                  ip_address=$(echo "$line" | awk '{print $2}')

                                  printf "%-20s %-20s %-15s\n" "$container_name" "$network_name" "$ip_address"
                              done <<< "$network_info"
                          done

                          break_end
                          ;;

                      0)
                          break  # 跳出循环，退出菜单
                          ;;

                      *)
                          break  # 跳出循环，退出菜单
                          ;;
                  esac
              done
              ;;
          4)
              while true; do
                  clear
                  echo "Docker镜像列表"
                  docker image ls
                  echo ""
                  echo "镜像操作"
                  echo "------------------------"
                  echo "1. 获取指定镜像             3. 删除指定镜像"
                  echo "2. 更新指定镜像             4. 删除所有镜像"
                  echo "------------------------"
                  echo "0. 返回上一级选单"
                  echo "------------------------"
                  read -p "请输入你的选择: " sub_choice

                  case $sub_choice in
                      1)
                          read -p "请输入镜像名: " dockername
                          docker pull $dockername
                          ;;
                      2)
                          read -p "请输入镜像名: " dockername
                          docker pull $dockername
                          ;;
                      3)
                          read -p "请输入镜像名: " dockername
                          docker rmi -f $dockername
                          ;;
                      4)
                          read -p "$(echo -e "${Red}确定删除所有镜像吗？(Y/N): ${White}")" choice
                          case "$choice" in
                            [Yy])
                              docker rmi -f $(docker images -q)
                              ;;
                            [Nn])

                              ;;
                            *)
                              echo "无效的选择，请输入 Y 或 N。"
                              ;;
                          esac
                          ;;
                      0)
                          break  # 跳出循环，退出菜单
                          ;;

                      *)
                          break  # 跳出循环，退出菜单
                          ;;
                  esac
              done
              ;;

          5)
              while true; do
                  clear
                  echo "Docker网络列表"
                  echo "------------------------------------------------------------"
                  docker network ls
                  echo ""

                  echo "------------------------------------------------------------"
                  container_ids=$(docker ps -q)
                  printf "%-25s %-25s %-25s\n" "容器名称" "网络名称" "IP地址"

                  for container_id in $container_ids; do
                      container_info=$(docker inspect --format '{{ .Name }}{{ range $network, $config := .NetworkSettings.Networks }} {{ $network }} {{ $config.IPAddress }}{{ end }}' "$container_id")

                      container_name=$(echo "$container_info" | awk '{print $1}')
                      network_info=$(echo "$container_info" | cut -d' ' -f2-)

                      while IFS= read -r line; do
                          network_name=$(echo "$line" | awk '{print $1}')
                          ip_address=$(echo "$line" | awk '{print $2}')

                          printf "%-20s %-20s %-15s\n" "$container_name" "$network_name" "$ip_address"
                      done <<< "$network_info"
                  done

                  echo ""
                  echo "网络操作"
                  echo "------------------------"
                  echo "1. 创建网络"
                  echo "2. 加入网络"
                  echo "3. 退出网络"
                  echo "4. 删除网络"
                  echo "------------------------"
                  echo "0. 返回上一级选单"
                  echo "------------------------"
                  read -p "请输入你的选择: " sub_choice

                  case $sub_choice in
                      1)
                          read -p "设置新网络名: " dockernetwork
                          docker network create $dockernetwork
                          ;;
                      2)
                          read -p "加入网络名: " dockernetwork
                          read -p "那些容器加入该网络: " dockername
                          docker network connect $dockernetwork $dockername
                          echo ""
                          ;;
                      3)
                          read -p "退出网络名: " dockernetwork
                          read -p "那些容器退出该网络: " dockername
                          docker network disconnect $dockernetwork $dockername
                          echo ""
                          ;;

                      4)
                          read -p "请输入要删除的网络名: " dockernetwork
                          docker network rm $dockernetwork
                          ;;
                      0)
                          break  # 跳出循环，退出菜单
                          ;;

                      *)
                          break  # 跳出循环，退出菜单
                          ;;
                  esac
              done
              ;;

          6)
              while true; do
                  clear
                  echo "Docker卷列表"
                  docker volume ls
                  echo ""
                  echo "卷操作"
                  echo "------------------------"
                  echo "1. 创建新卷"
                  echo "2. 删除卷"
                  echo "------------------------"
                  echo "0. 返回上一级选单"
                  echo "------------------------"
                  read -p "请输入你的选择: " sub_choice

                  case $sub_choice in
                      1)
                          read -p "设置新卷名: " dockerjuan
                          docker volume create $dockerjuan

                          ;;
                      2)
                          read -p "输入删除卷名: " dockerjuan
                          docker volume rm $dockerjuan

                          ;;
                      0)
                          break  # 跳出循环，退出菜单
                          ;;

                      *)
                          break  # 跳出循环，退出菜单
                          ;;
                  esac
              done
              ;;
          7)
              clear
              read -p "$(echo -e "${Yellow}确定清理无用的镜像容器网络吗？(Y/N): ${White}")" choice
              case "$choice" in
                [Yy])
                  docker system prune -af --volumes
                  ;;
                [Nn])
                  ;;
                *)
                  echo "无效的选择，请输入 Y 或 N。"
                  ;;
              esac
              ;;
          20)
              clear
              read -p "$(echo -e "${Red}确定卸载docker环境吗？(Y/N): ${White}")" choice
              case "$choice" in
                [Yy])
                  docker rm $(docker ps -a -q) && docker rmi $(docker images -q) && docker network prune
                  remove docker docker-ce docker-compose docker-ce-cli containerd.io > /dev/null 2>&1
                  ;;
                [Nn])
                  ;;
                *)
                  echo "无效的选择，请输入 Y 或 N。"
                  ;;
              esac
              ;;
          0)
              back_main

              ;;
          *)
              echo "无效的输入!"
              ;;
      esac
      break_end


    done
    ;;

  7)
    while true; do
      clear
      echo "▶ 功能脚本合集"
      echo ""
      echo "----功能脚本------------------"
      echo "1. WARP管理 ▶ "
      echo "2. 甲骨文云脚本合集 ▶"
      echo ""
      echo "----网络线路测速-----------"
      echo "11. besttrace三网回程延迟路由测试"
      echo "12. mtr_trace三网回程线路测试"
      echo "13. Superspeed三网测速"
      echo "14. nxtrace快速回程测试脚本"
      echo "15. nxtrace指定IP回程测试脚本"
      echo "16. ludashi2020三网线路测试"
      echo "17. i-abc多功能测速脚本"
      echo ""
      echo "----硬件性能测试----------"
      echo "21. yabs性能测试"
      echo "22. icu/gb5 CPU性能测试脚本"
      echo ""
      echo "----IP及解锁状态检测------"
      echo "25. ChatGPT解锁状态检测"
      echo "26. Region流媒体解锁测试"
      echo "27. Yeahwu流媒体解锁检测"
      echo "28. XYkt_IP质量体检脚本"
      echo ""
      echo "----综合性测试-----------"
      echo "31. bench性能测试"
      echo "32. spiritysdx融合怪测评"
      echo "33. NodeQuality测评脚本"
      echo ""
      echo "------------------------"
      echo "0. 返回主菜单"
      echo "------------------------"
      read -p "请输入你的选择: " sub_choice

      case $sub_choice in
          1)
            clear
            install wget
            wget -N https://gitlab.com/fscarmen/warp/-/raw/main/menu.sh && bash menu.sh [option] [lisence/url/token]
            ;;
          2)
          while true; do
                  clear
                  echo "▶ 甲骨文云脚本合集"
                  echo "------------------------"
                  echo "1. 安装闲置机器活跃脚本"
                  echo "2. 卸载闲置机器活跃脚本"
                  echo "------------------------"
                  echo "3. DD重装系统脚本"
                  echo "4. R探长开机脚本"
                  echo "------------------------"
                  echo "5. 开启ROOT密码登录模式"
                  echo "------------------------"
                  echo "0. 返回主菜单"
                  echo "------------------------"
                  read -p "请输入你的选择: " sub_choice

                  case $sub_choice in
                      1)
                          clear
                          echo "活跃脚本: CPU占用10-20% 内存占用15% "
                          read -p "确定安装吗？(Y/N): " choice
                          case "$choice" in
                            [Yy])

                              install_docker

                              # 设置默认值
                              DEFAULT_CPU_CORE=1
                              DEFAULT_CPU_UTIL="10-20"
                              DEFAULT_MEM_UTIL=20
                              DEFAULT_SPEEDTEST_INTERVAL=120

                              # 提示用户输入CPU核心数和占用百分比，如果回车则使用默认值
                              read -p "请输入CPU核心数 [默认: $DEFAULT_CPU_CORE]: " cpu_core
                              cpu_core=${cpu_core:-$DEFAULT_CPU_CORE}

                              read -p "请输入CPU占用百分比范围（例如10-20） [默认: $DEFAULT_CPU_UTIL]: " cpu_util
                              cpu_util=${cpu_util:-$DEFAULT_CPU_UTIL}

                              read -p "请输入内存占用百分比 [默认: $DEFAULT_MEM_UTIL]: " mem_util
                              mem_util=${mem_util:-$DEFAULT_MEM_UTIL}

                              read -p "请输入Speedtest间隔时间（秒） [默认: $DEFAULT_SPEEDTEST_INTERVAL]: " speedtest_interval
                              speedtest_interval=${speedtest_interval:-$DEFAULT_SPEEDTEST_INTERVAL}

                              # 运行Docker容器
                              docker run -itd --name=lookbusy --restart=always \
                                  -e TZ=Asia/Shanghai \
                                  -e CPU_UTIL="$cpu_util" \
                                  -e CPU_CORE="$cpu_core" \
                                  -e MEM_UTIL="$mem_util" \
                                  -e SPEEDTEST_INTERVAL="$speedtest_interval" \
                                  fogforest/lookbusy

                              ;;
                            [Nn])

                              ;;
                            *)
                              echo "无效的选择，请输入 Y 或 N。"
                              ;;
                          esac
                          ;;
                      2)
                          clear
                          docker rm -f lookbusy
                          docker rmi fogforest/lookbusy
                          ;;

                      3)
                      clear
                      echo "请备份数据，将为你重装系统，预计花费15分钟。"
                      read -p "确定继续吗？(Y/N): " choice

                      case "$choice" in
                        [Yy])
                          while true; do
                            read -p "请选择要重装的系统:  1. Debian12 | 2. Ubuntu20.04 : " sys_choice

                            case "$sys_choice" in
                              1)
                                xitong="-d 12"
                                break  # 结束循环
                                ;;
                              2)
                                xitong="-u 20.04"
                                break  # 结束循环
                                ;;
                              *)
                                echo "无效的选择，请重新输入。"
                                ;;
                            esac
                          done

                          read -p "请输入你重装后的密码: " vpspasswd
                          install wget
                          bash <(wget --no-check-certificate -qO- 'https://raw.githubusercontent.com/MoeClub/Note/master/InstallNET.sh') $xitong -v 64 -p $vpspasswd -port 22
                          ;;
                        [Nn])
                          echo "已取消"
                          ;;
                        *)
                          echo "无效的选择，请输入 Y 或 N。"
                          ;;
                      esac
                          ;;

                      4)
                          clear
                          echo "该功能暂不支持！"
                          ;;
                      5)
                          clear
                          add_sshpasswd

                          ;;
                      0)
                          back_main

                          ;;
                      *)
                          echo "无效的输入!"
                          ;;
                  esac
                  break_end

                done
                ;;
            
          11)
              clear
              install wget
              wget -qO- git.io/besttrace | bash
              ;;
          12)
              clear
              curl https://raw.githubusercontent.com/zhucaidan/mtr_trace/main/mtr_trace.sh | bash
              ;;
          13)
              clear
              bash <(curl -Lso- https://git.io/superspeed_uxh)
              ;;
          14)
              clear
              curl nxtrace.org/nt |bash
              nexttrace --fast-trace --tcp
              ;;
          15)
              clear

              echo "可参考的IP列表"
              echo "------------------------"
              echo "北京电信: 219.141.136.12"
              echo "北京联通: 202.106.50.1"
              echo "北京移动: 221.179.155.161"
              echo "上海电信: 202.96.209.133"
              echo "上海联通: 210.22.97.1"
              echo "上海移动: 211.136.112.200"
              echo "广州电信: 58.60.188.222"
              echo "广州联通: 210.21.196.6"
              echo "广州移动: 120.196.165.24"
              echo "成都电信: 61.139.2.69"
              echo "成都联通: 119.6.6.6"
              echo "成都移动: 211.137.96.205"
              echo "湖南电信: 36.111.200.100"
              echo "湖南联通: 42.48.16.100"
              echo "湖南移动: 39.134.254.6"
              echo "------------------------"

              read -p "输入一个指定IP: " testip
              curl nxtrace.org/nt |bash
              nexttrace $testip
              ;;

          16)
              clear
              curl https://raw.githubusercontent.com/ludashi2020/backtrace/main/install.sh -sSf | sh
              ;;

          17)
              clear
              bash <(curl -sL bash.icu/speedtest)
              ;;

          21)
              clear
              new_swap=1024
              add_swap
              curl -sL yabs.sh | bash -s -- -i -5
              ;;
          22)
              clear
              new_swap=1024
              add_swap
              bash <(curl -sL bash.icu/gb5)
              ;;
          25)
              clear
              bash <(curl -Ls https://cdn.jsdelivr.net/gh/missuo/OpenAI-Checker/openai.sh)
              ;;
          26)
              clear
              bash <(curl -L -s check.unlock.media)
              ;;
          27)
              clear
              install wget
              wget -qO- https://github.com/yeahwu/check/raw/main/check.sh | bash
              ;;
          28)
              clear
              bash <(curl -Ls IP.Check.Place)
              ;;
          31)
              clear
              curl -Lso- bench.sh | bash
              ;;
          32)
              clear
              curl -L https://gitlab.com/spiritysdx/za/-/raw/main/ecs.sh -o ecs.sh && chmod +x ecs.sh && bash ecs.sh
              ;;
          33)
              clear
              bash <(curl -sL https://run.NodeQuality.com)
              ;;
          0)
              back_main
              ;;
          *)
              echo "无效的输入!"
              ;;
      esac
      break_end

    done
    ;;

  8)
    while true; do
      clear
      echo "▶ 面板工具"
      echo "------------------------"
      echo "1. 1Panel新一代管理面板                 2. aaPanel宝塔国际版"
      echo "3. 宝塔面板官方版                       4. 3X-UI代理面板"
      echo "5. AList多存储文件列表程序              6. Ubuntu远程桌面网页版"
      echo "7. 哪吒探针V0主控面板                   8. QB离线BT磁力下载面板"
      echo "9. Poste.io邮件服务器程序               10. RocketChat多人在线聊天系统"
      echo "11. 禅道项目管理软件                    12. 青龙面板定时任务管理平台"
      echo "13. Cloudreve网盘                       14. 简单图床图片管理程序"
      echo "15. emby多媒体管理系统                  16. Speedtest测速面板"
      echo "17. AdGuardHome去广告软件               18. onlyoffice在线办公OFFICE"
      echo "19. 雷池WAF防火墙面板                   20. portainer容器管理面板"
      echo "21. VScode网页版                        22. UptimeKuma监控工具"
      echo "23. Memos网页备忘录                     24. Webtop远程桌面网页版"
      echo "25. Nextcloud网盘                       26. QD-Today定时任务管理框架"
      echo "27. Dockge容器堆栈管理面板              28. LibreSpeed测速工具"
      echo "29. searxng聚合搜索站                   30. PhotoPrism私有相册系统"
      echo "31. StirlingPDF工具大全                 32. drawio免费的在线图表软件"
      echo "33. Sun-Panel导航面板                   34. Pingvin-Share文件分享平台"
      echo "35. 极简朋友圈                          36. LobeChatAI聊天聚合网站"
      echo "37. MyIP工具箱                          38. NginxProxyManager可视化面板"
      echo "------------------------"
      echo "51. PVE开小鸡面板"
      echo "------------------------"
      echo "0. 返回主菜单"
      echo "------------------------"
      read -p "请输入你的选择: " sub_choice

      case $sub_choice in
          1)
            lujing="command -v 1pctl &> /dev/null"
            panelname="1Panel"

            gongneng1="1pctl user-info"
            gongneng1_1="1pctl update password"
            gongneng2="1pctl uninstall"
            gongneng2_1=""
            gongneng2_2=""

            panelurl="https://1panel.cn/"


            centos_mingling="curl -sSL https://resource.fit2cloud.com/1panel/package/quick_start.sh -o quick_start.sh"
            centos_mingling2="sh quick_start.sh"

            ubuntu_mingling="curl -sSL https://resource.fit2cloud.com/1panel/package/quick_start.sh -o quick_start.sh"
            ubuntu_mingling2="bash quick_start.sh"

            install_panel
              ;;
          2)

            lujing="[ -d "/www/server/panel" ]"
            panelname="aapanel"

            gongneng1="bt"
            gongneng1_1=""
            gongneng2="curl -o bt-uninstall.sh http://download.bt.cn/install/bt-uninstall.sh > /dev/null 2>&1 && chmod +x bt-uninstall.sh && ./bt-uninstall.sh"
            gongneng2_1="chmod +x bt-uninstall.sh"
            gongneng2_2="./bt-uninstall.sh"

            panelurl="https://www.aapanel.com/new/index.html"

            centos_mingling="wget -O install.sh http://www.aapanel.com/script/install_6.0_en.sh"
            centos_mingling2="bash install.sh aapanel"

            ubuntu_mingling="wget -O install.sh http://www.aapanel.com/script/install-ubuntu_6.0_en.sh"
            ubuntu_mingling2="bash install.sh aapanel"

            install_panel

              ;;
          3)


            lujing="[ -d "/www/server/panel" ]"
            panelname="宝塔面板"

            gongneng1="bt"
            gongneng1_1=""
            gongneng2="curl -o bt-uninstall.sh http://download.bt.cn/install/bt-uninstall.sh > /dev/null 2>&1 && chmod +x bt-uninstall.sh && ./bt-uninstall.sh"
            gongneng2_1="chmod +x bt-uninstall.sh"
            gongneng2_2="./bt-uninstall.sh"

            panelurl="https://www.bt.cn/new/index.html"


            centos_mingling="wget -O install.sh https://download.bt.cn/install/install_6.0.sh"
            centos_mingling2="sh install.sh ed8484bec"

            ubuntu_mingling="wget -O install.sh https://download.bt.cn/install/install-ubuntu_6.0.sh"
            ubuntu_mingling2="bash install.sh ed8484bec"

            install_panel
              ;;
          4)
            #询问用户是否要安装3XUI
            read -p "是否要安装3X-UI最新版？(y/n): " choice
            if [ "$choice" == "y" ]; then
                clear
                install net-tools
                bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh)
                exit 0
            else
                back_main
            fi
            ;;

          5)

            docker_name="alist"
            docker_img="xhofe/alist:latest"
            docker_port=5244
            docker_rum="docker run -d \
                                --restart=always \
                                -v /home/docker/alist:/opt/alist/data \
                                -p 5244:5244 \
                                -e PUID=0 \
                                -e PGID=0 \
                                -e UMASK=022 \
                                --name="alist" \
                                xhofe/alist:latest"
            docker_describe="一个支持多种存储，支持网页浏览和 WebDAV 的文件列表程序，由 gin 和 Solidjs 驱动"
            docker_url="官网介绍: https://alist.nn.ci/zh/"
            docker_use="docker exec -it alist ./alist admin random"
            docker_passwd=""

            docker_app

              ;;

          6)
            docker_name="ubuntu-novnc"
            docker_img="fredblgr/ubuntu-novnc:20.04"
            docker_port=6080
            rootpasswd=$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c16)
            docker_rum="docker run -d \
                                --name ubuntu-novnc \
                                -p 6080:80 \
                                -v /home/docker/ubuntu-novnc:/workspace:rw \
                                -e HTTP_PASSWORD=$rootpasswd \
                                -e RESOLUTION=1280x720 \
                                --restart=always \
                                fredblgr/ubuntu-novnc:20.04"
            docker_describe="一个网页版Ubuntu远程桌面，挺好用的！"
            docker_url="官网介绍: https://hub.docker.com/r/fredblgr/ubuntu-novnc"
            docker_use="echo \"用户名: root\""
            docker_passwd="echo \"密码: $rootpasswd\""

            docker_app

              ;;
          7)
            clear
            curl -L https://raw.githubusercontent.com/nezhahq/scripts/refs/heads/v0/install.sh -o nezha.sh && chmod +x nezha.sh 
            ./nezha.sh
              ;;

          8)

            docker_name="qbittorrent"
            docker_img="lscr.io/linuxserver/qbittorrent:latest"
            docker_port=8081
            docker_rum="docker run -d \
                                  --name=qbittorrent \
                                  -e PUID=1000 \
                                  -e PGID=1000 \
                                  -e TZ=Etc/UTC \
                                  -e WEBUI_PORT=8081 \
                                  -p 8081:8081 \
                                  -p 6881:6881 \
                                  -p 6881:6881/udp \
                                  -v /home/docker/qbittorrent/config:/config \
                                  -v /home/docker/qbittorrent/downloads:/downloads \
                                  --restart unless-stopped \
                                  lscr.io/linuxserver/qbittorrent:latest"
            docker_describe="qbittorrent离线BT磁力下载服务"
            docker_url="官网介绍: https://hub.docker.com/r/linuxserver/qbittorrent"
            docker_use="sleep 3"
            docker_passwd="docker logs qbittorrent"

            docker_app

              ;;

          9)
            if docker inspect mailserver &>/dev/null; then

                    clear
                    echo "poste.io已安装，访问地址: "
                    yuming=$(cat /home/docker/mail.txt)
                    echo "https://$yuming"
                    echo ""

                    echo "应用操作"
                    echo "------------------------"
                    echo "1. 更新应用             2. 卸载应用"
                    echo "------------------------"
                    echo "0. 返回上一级选单"
                    echo "------------------------"
                    read -p "请输入你的选择: " sub_choice

                    case $sub_choice in
                        1)
                            clear
                            docker rm -f mailserver
                            docker rmi -f analogic/poste.io

                            yuming=$(cat /home/docker/mail.txt)
                            docker run \
                                --net=host \
                                -e TZ=Europe/Prague \
                                -v /home/docker/mail:/data \
                                --name "mailserver" \
                                -h "$yuming" \
                                --restart=always \
                                -d analogic/poste.io

                            clear
                            echo "poste.io已经安装完成"
                            echo "------------------------"
                            echo "您可以使用以下地址访问poste.io:"
                            echo "https://$yuming"
                            echo ""
                            ;;
                        2)
                            clear
                            docker rm -f mailserver
                            docker rmi -f analogic/poste.io
                            rm /home/docker/mail.txt
                            rm -rf /home/docker/mail
                            echo "应用已卸载"
                            ;;
                        0)
                            break  # 跳出循环，退出菜单
                            ;;
                        *)
                            break  # 跳出循环，退出菜单
                            ;;
                    esac
            else
                clear
                install telnet

                clear
                echo ""
                echo "端口检测"
                port=25
                timeout=3

                if echo "quit" | timeout $timeout telnet smtp.qq.com $port | grep 'Connected'; then
                  echo -e "${Green}端口 $port 当前可用${White}"
                else
                  echo -e "${Red}端口 $port 当前不可用${White}"
                fi
                echo "------------------------"
                echo ""


                echo "安装提示"
                echo "poste.io一个邮件服务器，确保80和443端口没被占用，确保25端口开放"
                echo "官网介绍: https://hub.docker.com/r/analogic/poste.io"
                echo ""

                # 提示用户确认安装
                read -p "确定安装poste.io吗？(Y/N): " choice
                case "$choice" in
                    [Yy])
                    clear

                    read -p "请设置邮箱域名 例如 mail.yuming.com : " yuming
                    mkdir -p /home/docker      # 递归创建目录
                    echo "$yuming" > /home/docker/mail.txt  # 写入文件
                    echo "------------------------"
                    ip_address
                    echo "先解析这些DNS记录"
                    echo "A           mail            $ipv4_address"
                    echo "CNAME       imap            $yuming"
                    echo "CNAME       pop             $yuming"
                    echo "CNAME       smtp            $yuming"
                    echo "MX          @               $yuming"
                    echo "TXT         @               v=spf1 mx ~all"
                    echo "TXT         ?               ?"
                    echo ""
                    echo "------------------------"
                    echo "按任意键继续..."
                    read -n 1 -s -r -p ""

                    install_docker

                    docker run \
                        --net=host \
                        -e TZ=Europe/Prague \
                        -v /home/docker/mail:/data \
                        --name "mailserver" \
                        -h "$yuming" \
                        --restart=always \
                        -d analogic/poste.io

                    clear
                    echo "poste.io已经安装完成"
                    echo "------------------------"
                    echo "您可以使用以下地址访问poste.io:"
                    echo "https://$yuming"
                    echo ""

                        ;;
                    [Nn])
                        ;;
                    *)
                        ;;
                esac
            fi
              ;;

          10)
            if docker inspect rocketchat &>/dev/null; then


                    clear
                    echo "rocket.chat已安装，访问地址: "
                    ip_address
                    echo "http:$ipv4_address:3897"
                    echo ""

                    echo "应用操作"
                    echo "------------------------"
                    echo "1. 更新应用             2. 卸载应用"
                    echo "------------------------"
                    echo "0. 返回上一级选单"
                    echo "------------------------"
                    read -p "请输入你的选择: " sub_choice

                    case $sub_choice in
                        1)
                            clear
                            docker rm -f rocketchat
                            docker rmi -f rocket.chat:6.3


                            docker run --name rocketchat --restart=always -p 3897:3000 --link db --env ROOT_URL=http://localhost --env MONGO_OPLOG_URL=mongodb://db:27017/rs5 -d rocket.chat

                            clear
                            ip_address
                            echo "rocket.chat已经安装完成"
                            echo "------------------------"
                            echo "多等一会，您可以使用以下地址访问rocket.chat:"
                            echo "http:$ipv4_address:3897"
                            echo ""
                            ;;
                        2)
                            clear
                            docker rm -f rocketchat
                            docker rmi -f rocket.chat
                            docker rmi -f rocket.chat:6.3
                            docker rm -f db
                            docker rmi -f mongo:latest
                            # docker rmi -f mongo:6
                            rm -rf /home/docker/mongo
                            echo "应用已卸载"
                            ;;
                        0)
                            break  # 跳出循环，退出菜单
                            ;;
                        *)
                            break  # 跳出循环，退出菜单
                            ;;
                    esac
            else
                clear
                echo "安装提示"
                echo "rocket.chat国外知名开源多人聊天系统"
                echo "官网介绍: https://www.rocket.chat"
                echo ""

                # 提示用户确认安装
                read -p "确定安装rocket.chat吗？(Y/N): " choice
                case "$choice" in
                    [Yy])
                    clear
                    install_docker
                    docker run --name db -d --restart=always \
                        -v /home/docker/mongo/dump:/dump \
                        mongo:latest --replSet rs5 --oplogSize 256
                    sleep 1
                    docker exec -it db mongosh --eval "printjson(rs.initiate())"
                    sleep 5
                    docker run --name rocketchat --restart=always -p 3897:3000 --link db --env ROOT_URL=http://localhost --env MONGO_OPLOG_URL=mongodb://db:27017/rs5 -d rocket.chat

                    clear

                    ip_address
                    echo "rocket.chat已经安装完成"
                    echo "------------------------"
                    echo "多等一会，您可以使用以下地址访问rocket.chat:"
                    echo "http:$ipv4_address:3897"
                    echo ""

                        ;;
                    [Nn])
                        ;;
                    *)
                        ;;
                esac
            fi
              ;;



          11)
            docker_name="zentao-server"
            docker_img="idoop/zentao:latest"
            docker_port=82
            docker_rum="docker run -d -p 82:80 -p 3308:3306 \
                              -e ADMINER_USER="root" -e ADMINER_PASSWD="password" \
                              -e BIND_ADDRESS="false" \
                              -v /home/docker/zentao-server/:/opt/zbox/ \
                              --add-host smtp.exmail.qq.com:163.177.90.125 \
                              --name zentao-server \
                              --restart=always \
                              idoop/zentao:latest"
            docker_describe="禅道是通用的项目管理软件"
            docker_url="官网介绍: https://www.zentao.net/"
            docker_use="echo \"初始用户名: admin\""
            docker_passwd="echo \"初始密码: 123456\""
            docker_app

              ;;

          12)
            docker_name="qinglong"
            docker_img="whyour/qinglong:latest"
            docker_port=5700
            docker_rum="docker run -d \
                      -v /home/docker/qinglong/data:/ql/data \
                      -p 5700:5700 \
                      --name qinglong \
                      --hostname qinglong \
                      --restart unless-stopped \
                      whyour/qinglong:latest"
            docker_describe="青龙面板是一个定时任务管理平台"
            docker_url="官网介绍: https://github.com/whyour/qinglong"
            docker_use=""
            docker_passwd=""
            docker_app

              ;;
          13)
            if docker inspect cloudreve &>/dev/null; then

                    clear
                    echo "cloudreve已安装，访问地址: "
                    ip_address
                    echo "http:$ipv4_address:5212"
                    echo ""

                    echo "应用操作"
                    echo "------------------------"
                    echo "1. 更新应用             2. 卸载应用"
                    echo "------------------------"
                    echo "0. 返回上一级选单"
                    echo "------------------------"
                    read -p "请输入你的选择: " sub_choice

                    case $sub_choice in
                        1)
                            clear
                            docker rm -f cloudreve
                            docker rmi -f cloudreve/cloudreve:latest
                            docker rm -f aria2
                            docker rmi -f p3terx/aria2-pro

                            cd /home/ && mkdir -p docker/cloud && cd docker/cloud && mkdir temp_data && mkdir -vp cloudreve/{uploads,avatar} && touch cloudreve/conf.ini && touch cloudreve/cloudreve.db && mkdir -p aria2/config && mkdir -p data/aria2 && chmod -R 777 data/aria2
                            curl -o /home/docker/cloud/docker-compose.yml https://raw.githubusercontent.com/railzen/CherryScript/main/tools/config/cloudreve-docker-compose.yml
                            cd /home/docker/cloud/ && docker-compose up -d


                            clear
                            echo "cloudreve已经安装完成"
                            echo "------------------------"
                            echo "您可以使用以下地址访问cloudreve:"
                            ip_address
                            echo "http:$ipv4_address:5212"
                            sleep 3
                            docker logs cloudreve
                            echo ""
                            ;;
                        2)
                            clear
                            docker rm -f cloudreve
                            docker rmi -f cloudreve/cloudreve:latest
                            docker rm -f aria2
                            docker rmi -f p3terx/aria2-pro
                            rm -rf /home/docker/cloud
                            echo "应用已卸载"
                            ;;
                        0)
                            break  # 跳出循环，退出菜单
                            ;;
                        *)
                            break  # 跳出循环，退出菜单
                            ;;
                    esac
            else
                clear
                echo "安装提示"
                echo "cloudreve是一个支持多家云存储的网盘系统"
                echo "官网介绍: https://cloudreve.org/"
                echo ""

                # 提示用户确认安装
                read -p "确定安装cloudreve吗？(Y/N): " choice
                case "$choice" in
                    [Yy])
                    clear
                    install_docker
                    cd /home/ && mkdir -p docker/cloud && cd docker/cloud && mkdir temp_data && mkdir -vp cloudreve/{uploads,avatar} && touch cloudreve/conf.ini && touch cloudreve/cloudreve.db && mkdir -p aria2/config && mkdir -p data/aria2 && chmod -R 777 data/aria2
                    curl -o /home/docker/cloud/docker-compose.yml https://raw.githubusercontent.com/railzen/CherryScript/main/tools/config/cloudreve-docker-compose.yml
                    cd /home/docker/cloud/ && docker-compose up -d


                    clear
                    echo "cloudreve已经安装完成"
                    echo "------------------------"
                    echo "您可以使用以下地址访问cloudreve:"
                    ip_address
                    echo "http:$ipv4_address:5212"
                    sleep 3
                    docker logs cloudreve
                    echo ""

                        ;;
                    [Nn])
                        ;;
                    *)
                        ;;
                esac
            fi

              ;;

          14)
            docker_name="easyimage"
            docker_img="ddsderek/easyimage:latest"
            docker_port=85
            docker_rum="docker run -d \
                      --name easyimage \
                      -p 85:80 \
                      -e TZ=Asia/Shanghai \
                      -e PUID=1000 \
                      -e PGID=1000 \
                      -v /home/docker/easyimage/config:/app/web/config \
                      -v /home/docker/easyimage/i:/app/web/i \
                      --restart unless-stopped \
                      ddsderek/easyimage:latest"
            docker_describe="简单图床是一个简单的图床程序"
            docker_url="官网介绍: https://github.com/icret/EasyImages2.0"
            docker_use=""
            docker_passwd=""
            docker_app
              ;;

          15)
            docker_name="emby"
            docker_img="linuxserver/emby:latest"
            docker_port=8096
            docker_rum="docker run -d --name=emby --restart=always \
                        -v /homeo/docker/emby/config:/config \
                        -v /homeo/docker/emby/share1:/mnt/share1 \
                        -v /homeo/docker/emby/share2:/mnt/share2 \
                        -v /mnt/notify:/mnt/notify \
                        -p 8096:8096 -p 8920:8920 \
                        -e UID=1000 -e GID=100 -e GIDLIST=100 \
                        linuxserver/emby:latest"
            docker_describe="emby是一个主从式架构的媒体服务器软件，可以用来整理服务器上的视频和音频，并将音频和视频流式传输到客户端设备"
            docker_url="官网介绍: https://emby.media/"
            docker_use=""
            docker_passwd=""
            docker_app
              ;;

          16)
            docker_name="looking-glass"
            docker_img="wikihostinc/looking-glass-server"
            docker_port=89
            docker_rum="docker run -d --name looking-glass --restart always -p 89:80 wikihostinc/looking-glass-server"
            docker_describe="Speedtest测速面板是一个VPS网速测试工具，多项测试功能，还可以实时监控VPS进出站流量"
            docker_url="官网介绍: https://github.com/wikihost-opensource/als"
            docker_use=""
            docker_passwd=""
            docker_app

              ;;
          17)

            docker_name="adguardhome"
            docker_img="adguard/adguardhome"
            docker_port=3000
            docker_rum="docker run -d \
                            --name adguardhome \
                            -v /home/docker/adguardhome/work:/opt/adguardhome/work \
                            -v /home/docker/adguardhome/conf:/opt/adguardhome/conf \
                            -p 53:53/tcp \
                            -p 53:53/udp \
                            -p 3000:3000/tcp \
                            --restart always \
                            adguard/adguardhome"
            docker_describe="AdGuardHome是一款全网广告拦截与反跟踪软件，未来将不止是一个DNS服务器。"
            docker_url="官网介绍: https://hub.docker.com/r/adguard/adguardhome"
            docker_use=""
            docker_passwd=""
            docker_app

              ;;


          18)

            docker_name="onlyoffice"
            docker_img="onlyoffice/documentserver"
            docker_port=8082
            docker_rum="docker run -d -p 8082:80 \
                        --restart=always \
                        --name onlyoffice \
                        -v /home/docker/onlyoffice/DocumentServer/logs:/var/log/onlyoffice  \
                        -v /home/docker/onlyoffice/DocumentServer/data:/var/www/onlyoffice/Data  \
                         onlyoffice/documentserver"
            docker_describe="onlyoffice是一款开源的在线office工具，太强大了！"
            docker_url="官网介绍: https://www.onlyoffice.com/"
            docker_use=""
            docker_passwd=""
            docker_app

              ;;

          19)

            if docker inspect safeline-tengine &>/dev/null; then

                    clear
                    echo "雷池已安装，访问地址: "
                    ip_address
                    echo "http:$ipv4_address:9443"
                    echo ""

                    echo "应用操作"
                    echo "------------------------"
                    echo "1. 更新应用             2. 卸载应用"
                    echo "------------------------"
                    echo "0. 返回上一级选单"
                    echo "------------------------"
                    read -p "请输入你的选择: " sub_choice

                    case $sub_choice in
                        1)
                            clear
                            echo "暂不支持"
                            echo ""
                            ;;
                        2)

                            clear
                            echo "cd命令到安装目录下执行: docker compose down"
                            echo ""
                            ;;
                        0)
                            break  # 跳出循环，退出菜单
                            ;;
                        *)
                            break  # 跳出循环，退出菜单
                            ;;
                    esac
            else
                clear
                echo "安装提示"
                echo "雷池是长亭科技开发的WAF站点防火墙程序面板，可以反代站点进行自动化防御"
                echo "80和443端口不能被占用，无法与宝塔，1panel，npm，ldnmp建站共存"
                echo "官网介绍: https://github.com/chaitin/safeline"
                echo ""

                # 提示用户确认安装
                read -p "确定安装吗？(Y/N): " choice
                case "$choice" in
                    [Yy])
                    clear
                    install_docker
                    bash -c "$(curl -fsSLk https://waf-ce.chaitin.cn/release/latest/setup.sh)"

                    clear
                    echo "雷池WAF面板已经安装完成"
                    echo "------------------------"
                    echo "您可以使用以下地址访问:"
                    ip_address
                    echo "http:$ipv4_address:9443"
                    echo ""

                        ;;
                    [Nn])
                        ;;
                    *)
                        ;;
                esac
            fi

              ;;

          20)
            docker_name="portainer"
            docker_img="portainer/portainer"
            docker_port=9050
            docker_rum="docker run -d \
                    --name portainer \
                    -p 9050:9000 \
                    -v /var/run/docker.sock:/var/run/docker.sock \
                    -v /home/docker/portainer:/data \
                    --restart always \
                    portainer/portainer"
            docker_describe="portainer是一个轻量级的docker容器管理面板"
            docker_url="官网介绍: https://www.portainer.io/"
            docker_use=""
            docker_passwd=""
            docker_app

              ;;

          21)
            docker_name="vscode-web"
            docker_img="codercom/code-server"
            docker_port=8180
            docker_rum="docker run -d -p 8180:8080 -v /home/docker/vscode-web:/home/coder/.local/share/code-server --name vscode-web --restart always codercom/code-server"
            docker_describe="VScode是一款强大的在线代码编写工具"
            docker_url="官网介绍: https://github.com/coder/code-server"
            docker_use="sleep 3"
            docker_passwd="docker exec vscode-web cat /home/coder/.config/code-server/config.yaml"
            docker_app
              ;;
          22)
            docker_name="uptime-kuma"
            docker_img="louislam/uptime-kuma:latest"
            docker_port=3003
            docker_rum="docker run -d \
                            --name=uptime-kuma \
                            -p 3003:3001 \
                            -v /home/docker/uptime-kuma/uptime-kuma-data:/app/data \
                            --restart=always \
                            louislam/uptime-kuma:latest"
            docker_describe="Uptime Kuma 易于使用的自托管监控工具"
            docker_url="官网介绍: https://github.com/louislam/uptime-kuma"
            docker_use=""
            docker_passwd=""
            docker_app
              ;;

          23)
            docker_name="memos"
            docker_img="ghcr.io/usememos/memos:latest"
            docker_port=5230
            docker_rum="docker run -d --name memos -p 5230:5230 -v /home/docker/memos:/var/opt/memos --restart always ghcr.io/usememos/memos:latest"
            docker_describe="Memos是一款轻量级、自托管的备忘录中心"
            docker_url="官网介绍: https://github.com/usememos/memos"
            docker_use=""
            docker_passwd=""
            docker_app
              ;;

          24)
            docker_name="webtop"
            docker_img="lscr.io/linuxserver/webtop:latest"
            docker_port=3083
            docker_rum="docker run -d \
                          --name=webtop \
                          --security-opt seccomp=unconfined \
                          -e PUID=1000 \
                          -e PGID=1000 \
                          -e TZ=Etc/UTC \
                          -e SUBFOLDER=/ \
                          -e TITLE=Webtop \
                          -e LC_ALL=zh_CN.UTF-8 \
                          -e DOCKER_MODS=linuxserver/mods:universal-package-install \
                          -e INSTALL_PACKAGES=font-noto-cjk \
                          -p 3083:3000 \
                          -v /home/docker/webtop/data:/config \
                          -v /var/run/docker.sock:/var/run/docker.sock \
                          --device /dev/dri:/dev/dri \
                          --shm-size="1gb" \
                          --restart unless-stopped \
                          lscr.io/linuxserver/webtop:latest"

            docker_describe="webtop基于 Alpine、Ubuntu、Fedora 和 Arch 的容器，包含官方支持的完整桌面环境，可通过任何现代 Web 浏览器访问"
            docker_url="官网介绍: https://docs.linuxserver.io/images/docker-webtop/"
            docker_use=""
            docker_passwd=""
            docker_app
              ;;

          25)
            docker_name="nextcloud"
            docker_img="nextcloud:latest"
            docker_port=8989
            rootpasswd=$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c16)
            docker_rum="docker run -d --name nextcloud --restart=always -p 8989:80 -v /home/docker/nextcloud:/var/www/html -e NEXTCLOUD_ADMIN_USER=nextcloud -e NEXTCLOUD_ADMIN_PASSWORD=$rootpasswd nextcloud"
            docker_describe="Nextcloud拥有超过 400,000 个部署，是您可以下载的最受欢迎的本地内容协作平台"
            docker_url="官网介绍: https://nextcloud.com/"
            docker_use="echo \"账号: nextcloud  密码: $rootpasswd\""
            docker_passwd=""
            docker_app
              ;;

          26)
            docker_name="qd"
            docker_img="qdtoday/qd:latest"
            docker_port=8923
            docker_rum="docker run -d --name qd -p 8923:80 -v /home/docker/qd/config:/usr/src/app/config qdtoday/qd"
            docker_describe="QD-Today是一个HTTP请求定时任务自动执行框架"
            docker_url="官网介绍: https://qd-today.github.io/qd/zh_CN/"
            docker_use=""
            docker_passwd=""
            docker_app
              ;;
          27)
            docker_name="dockge"
            docker_img="louislam/dockge:latest"
            docker_port=5003
            docker_rum="docker run -d --name dockge --restart unless-stopped -p 5003:5001 -v /var/run/docker.sock:/var/run/docker.sock -v /home/docker/dockge/data:/app/data -v  /home/docker/dockge/stacks:/home/docker/dockge/stacks -e DOCKGE_STACKS_DIR=/home/docker/dockge/stacks louislam/dockge"
            docker_describe="dockge是一个可视化的docker-compose容器管理面板"
            docker_url="官网介绍: https://github.com/louislam/dockge"
            docker_use=""
            docker_passwd=""
            docker_app
              ;;

          28)
            docker_name="speedtest"
            docker_img="ghcr.io/librespeed/speedtest:latest"
            docker_port=6681
            docker_rum="docker run -d \
                            --name speedtest \
                            --restart always \
                            -e MODE=standalone \
                            -p 6681:80 \
                            ghcr.io/librespeed/speedtest:latest"
            docker_describe="librespeed是用Javascript实现的轻量级速度测试工具，即开即用"
            docker_url="官网介绍: https://github.com/librespeed/speedtest"
            docker_use=""
            docker_passwd=""
            docker_app
              ;;

          29)
            docker_name="searxng"
            docker_img="alandoyle/searxng:latest"
            docker_port=8700
            docker_rum="docker run --name=searxng \
                            -d --init \
                            --restart=unless-stopped \
                            -v /home/docker/searxng/config:/etc/searxng \
                            -v /home/docker/searxng/templates:/usr/local/searxng/searx/templates/simple \
                            -v /home/docker/searxng/theme:/usr/local/searxng/searx/static/themes/simple \
                            -p 8700:8080/tcp \
                            alandoyle/searxng:latest"
            docker_describe="searxng是一个私有且隐私的搜索引擎站点"
            docker_url="官网介绍: https://hub.docker.com/r/alandoyle/searxng"
            docker_use=""
            docker_passwd=""
            docker_app
              ;;

          30)
            docker_name="photoprism"
            docker_img="photoprism/photoprism:latest"
            docker_port=2342
            rootpasswd=$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c16)
            docker_rum="docker run -d \
                            --name photoprism \
                            --restart always \
                            --security-opt seccomp=unconfined \
                            --security-opt apparmor=unconfined \
                            -p 2342:2342 \
                            -e PHOTOPRISM_UPLOAD_NSFW="true" \
                            -e PHOTOPRISM_ADMIN_PASSWORD="$rootpasswd" \
                            -v /home/docker/photoprism/storage:/photoprism/storage \
                            -v /home/docker/photoprism/Pictures:/photoprism/originals \
                            photoprism/photoprism"
            docker_describe="photoprism非常强大的私有相册系统"
            docker_url="官网介绍: https://www.photoprism.app/"
            docker_use="echo \"账号: admin  密码: $rootpasswd\""
            docker_passwd=""
            docker_app
              ;;


          31)
            docker_name="s-pdf"
            docker_img="frooodle/s-pdf:latest"
            docker_port=8020
            docker_rum="docker run -d \
                            --name s-pdf \
                            --restart=always \
                             -p 8020:8080 \
                             -v /home/docker/s-pdf/trainingData:/usr/share/tesseract-ocr/5/tessdata \
                             -v /home/docker/s-pdf/extraConfigs:/configs \
                             -v /home/docker/s-pdf/logs:/logs \
                             -e DOCKER_ENABLE_SECURITY=false \
                             frooodle/s-pdf:latest"
            docker_describe="这是一个强大的本地托管基于 Web 的 PDF 操作工具，使用 docker，允许您对 PDF 文件执行各种操作，例如拆分合并、转换、重新组织、添加图像、旋转、压缩等。"
            docker_url="官网介绍: https://github.com/Stirling-Tools/Stirling-PDF"
            docker_use=""
            docker_passwd=""
            docker_app
              ;;

          32)
            docker_name="drawio"
            docker_img="jgraph/drawio"
            docker_port=7080
            docker_rum="docker run -d --restart=always --name drawio -p 7080:8080 -v /home/docker/drawio:/var/lib/drawio jgraph/drawio"
            docker_describe="这是一个强大图表绘制软件。思维导图，拓扑图，流程图，都能画"
            docker_url="官网介绍: https://www.drawio.com/"
            docker_use=""
            docker_passwd=""
            docker_app
              ;;

          33)
            docker_name="sun-panel"
            docker_img="hslr/sun-panel"
            docker_port=3009
            docker_rum="docker run -d --restart=always -p 3009:3002 \
                            -v /home/docker/sun-panel/conf:/app/conf \
                            -v /home/docker/sun-panel/uploads:/app/uploads \
                            -v /home/docker/sun-panel/database:/app/database \
                            --name sun-panel \
                            hslr/sun-panel"
            docker_describe="Sun-Panel服务器、NAS导航面板、Homepage、浏览器首页"
            docker_url="官网介绍: https://doc.sun-panel.top/zh_cn/"
            docker_use="echo \"账号: admin@sun.cc  密码: 12345678\""
            docker_passwd=""
            docker_app
              ;;

          34)
            docker_name="pingvin-share"
            docker_img="stonith404/pingvin-share"
            docker_port=3060
            docker_rum="docker run -d \
                            --name pingvin-share \
                            --restart always \
                            -p 3060:3000 \
                            -v /home/docker/pingvin-share/data:/opt/app/backend/data \
                            stonith404/pingvin-share"
            docker_describe="Pingvin Share 是一个可自建的文件分享平台，是 WeTransfer 的一个替代品"
            docker_url="官网介绍: https://github.com/stonith404/pingvin-share"
            docker_use=""
            docker_passwd=""
            docker_app
              ;;


          35)
            docker_name="moments"
            docker_img="kingwrcy/moments:latest"
            docker_port=8035
            docker_rum="docker run -d --restart unless-stopped \
                            -p 8035:3000 \
                            -v /home/docker/moments/data:/app/data \
                            -v /etc/localtime:/etc/localtime:ro \
                            -v /etc/timezone:/etc/timezone:ro \
                            --name moments \
                            kingwrcy/moments:latest"
            docker_describe="极简朋友圈，高仿微信朋友圈，记录你的美好生活"
            docker_url="官网介绍: https://github.com/kingwrcy/moments?tab=readme-ov-file"
            docker_use="echo \"账号: admin  密码: a123456\""
            docker_passwd=""
            docker_app
              ;;



          36)
            docker_name="lobe-chat"
            docker_img="lobehub/lobe-chat:latest"
            docker_port=8036
            docker_rum="docker run -d -p 8036:3210 \
                            --name lobe-chat \
                            --restart=always \
                            lobehub/lobe-chat"
            docker_describe="LobeChat聚合市面上主流的AI大模型，ChatGPT/Claude/Gemini/Groq/Ollama"
            docker_url="官网介绍: https://github.com/lobehub/lobe-chat"
            docker_use=""
            docker_passwd=""
            docker_app
              ;;

          37)
            docker_name="myip"
            docker_img="ghcr.io/jason5ng32/myip:latest"
            docker_port=8037
            docker_rum="docker run -d -p 8037:18966 --name myip --restart always ghcr.io/jason5ng32/myip:latest"
            docker_describe="是一个多功能IP工具箱，可以查看自己IP信息及连通性，用网页面板呈现"
            docker_url="官网介绍: https://github.com/jason5ng32/MyIP/blob/main/README_ZH.md"
            docker_use=""
            docker_passwd=""
            docker_app
              ;;
           38)
            docker_name="npm"
            docker_img="jc21/nginx-proxy-manager:latest"
            docker_port=81
            docker_rum="docker run -d \
                          --name=$docker_name \
                          -p 80:80 \
                          -p 81:$docker_port \
                          -p 443:443 \
                          -v /home/docker/npm/data:/data \
                          -v /home/docker/npm/letsencrypt:/etc/letsencrypt \
                          --restart=always \
                          $docker_img"
            docker_describe="如果您已经安装了其他面板工具或者LDNMP建站环境，建议先卸载，再安装npm！"
            docker_url="官网介绍: https://nginxproxymanager.com/"
            docker_use="echo \"初始用户名: admin@example.com\""
            docker_passwd="echo \"初始密码: changeme\""

            docker_app

              ;;


          51)
          clear
          curl -L https://raw.githubusercontent.com/oneclickvirt/pve/main/scripts/install_pve.sh -o install_pve.sh && chmod +x install_pve.sh && bash install_pve.sh
              ;;
          0)
              back_main
              ;;
          *)
              echo "无效的输入!"
              ;;
      esac
      break_end

    done
    ;;

  9)
    clear
    curl -sS -O https://raw.githubusercontent.com/railzen/CherryScript/main/tools/Nat_Manage.sh && chmod +x Nat_Manage.sh && ./Nat_Manage.sh
    ;;

  10)
    while true; do
      clear
      echo "▶ 系统工具"
      echo "------------------------"
      echo "1. 设置脚本启动快捷键"
      echo "------------------------"
      echo "2. 修改登录密码"
      echo "3. ROOT密码登录模式"
      echo "4. ROOT私钥登录模式"
      echo "5. 修改SSH连接端口"
      echo "6. 开放所有端口"
      echo "7. 优化DNS地址"
      echo "8. 一键重装系统"
      echo "9. 禁用ROOT账户创建新账户"
      echo "10. 切换优先ipv4/ipv6"
      echo "11. 查看端口占用状态"
      echo "12. 修改虚拟内存大小"
      echo "13. 用户管理"
      echo "14. 用户/密码生成器"
      echo "15. 系统时区调整"
      echo "16. 设置BBR3加速"
      echo "17. 防火墙高级管理器"
      echo "18. 修改主机名"
      echo "19. 切换系统更新源"
      echo "20. 定时任务管理"
      echo "21. 本机host解析"
      echo "22. fail2banSSH防御程序"
      echo "23. 限流自动关机"
      echo "24. 安装Python最新版"
      echo "25. 添加开机启动服务"
      echo "26. 进行TCP窗口调优"
      echo "27. 网络初始化超时优化"
      echo "------------------------"
      echo "99. 重启服务器"
      echo "------------------------"
      echo "0. 返回主菜单"
      echo "------------------------"
      read -p "请输入你的选择: " sub_choice

      case $sub_choice in
          1)
              clear
              read -p "请输入你的快捷按键: " kuaijiejian
              ln -sf /usr/local/bin/ludo /usr/local/bin/${kuaijiejian}
              echo "快捷键已设置"
              ;;

          2)
              clear
              echo "设置你的登录密码"
              passwd
              ;;
          3)
              root_use
              add_sshpasswd
              ;;

          4)
                root_use
                echo "ROOT私钥登录模式"
                echo "------------------------"
                echo "1. 上传个人SSH密钥"
                echo "2. 生成新的SSH密钥"
                echo "3. 恢复密码登录模式"
                echo "------------------------"
                echo "0. 退出"
                echo "------------------------"
                read -p "请输入你的选择: " choice
                case $choice in
                    1)
                        clear
                        echo "使用密钥登录会关闭密码登录方式，需要使用私钥进行SSH登录, 按Ctrl+C取消"
                        add_sshkey
                        ;;

                    2)
                        # ssh-keygen -t rsa -b 4096 -C "xxxx@gmail.com" -f /root/.ssh/sshkey -N ""
                        ssh-keygen -t rsa -b 4096 -C "email@gmail.com" -f /root/.ssh/new_generated_sshkey -N ""
                        cat ~/.ssh/new_generated_sshkey.pub >> ~/.ssh/authorized_keys
                        chmod 600 ~/.ssh/authorized_keys
                        echo "使用密钥登录会关闭密码登录方式，需要使用私钥进行SSH登录"
                        echo -e "私钥信息已生成，${Yellow}该私钥只会显示一次${White}，请务必保存用于以后的SSH登录"
                        echo "--------------------------------"
                        cat ~/.ssh/new_generated_sshkey
                        echo "--------------------------------"
                        echo "Public Key:"
                        cat ~/.ssh/new_generated_sshkey.pub
                        echo "--------------------------------"
                        # 用完就删掉，不保存在服务器上避免泄露，密钥由用户自己保存
                        rm -f ~/.ssh/new_generated_sshkey*
                        sed -i -e 's/^\s*#\?\s*PermitRootLogin .*/PermitRootLogin prohibit-password/' \
                        -e 's/^\s*#\?\s*PasswordAuthentication .*/PasswordAuthentication no/' \
                        -e 's/^\s*#\?\s*PubkeyAuthentication .*/PubkeyAuthentication yes/' \
                        -e 's/^\s*#\?\s*ChallengeResponseAuthentication .*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
                        rm -rf /etc/ssh/sshd_config.d/* /etc/ssh/ssh_config.d/*
                        read -p "按任意键重启SSH以生效..." temp
                        restart_ssh
                        echo -e "${Green}ROOT私钥登录已开启，已关闭ROOT密码登录，重连将会生效${White}"
                        ;;
                    3)
                        sed -i 's/^\s*#\?\s*PermitRootLogin.*/PermitRootLogin yes/g' /etc/ssh/sshd_config;
                        sed -i 's/^\s*#\?\s*PasswordAuthentication.*/PasswordAuthentication yes/g' /etc/ssh/sshd_config;
                        rm -rf /etc/ssh/sshd_config.d/* /etc/ssh/ssh_config.d/*
                        restart_ssh
                        echo -e "${Green}ROOT登录设置完毕！${White}"
                        ;;
                    0)
                        break
                        ;;
                    *)
                        echo "无效的选择，请重新输入。"
                        ;;
                esac


              ;;

          5)
              root_use
              # 去掉 #Port 的注释
                clear
                sed -i 's/#Port/Port/' /etc/ssh/sshd_config

                # 读取当前的 SSH 端口号
                current_port=$(grep -E '^ *Port [0-9]+' /etc/ssh/sshd_config | awk '{print $2}')

                # 打印当前的 SSH 端口号
                echo -e "当前的 SSH 端口号是:  ${huang}$current_port ${bai}"

                echo "------------------------"
                echo "端口号范围1到65535之间的数字。（输入0退出）"

                # 提示用户输入新的 SSH 端口号
                read -p "请输入新的 SSH 端口号: " new_port

                # 判断端口号是否在有效范围内
                if [[ $new_port =~ ^[0-9]+$ ]]; then  # 检查输入是否为数字
                    if [[ $new_port -ge 1 && $new_port -le 65535 ]]; then
                        new_ssh_port
                    elif [[ $new_port -eq 0 ]]; then
                        break
                    else
                        echo "端口号无效，请输入1到65535之间的数字。"
                        break_end
                    fi
                else
                    echo "输入无效，请输入数字。"
                    break_end
                fi
              ;;

          6)
              root_use
              iptables_open
              remove iptables-persistent ufw firewalld iptables-services > /dev/null 2>&1
              echo "端口已全部开放"
              break
              ;;

          7)
            while true; do
                root_use
                echo "当前DNS地址"
                echo "------------------------"
                cat /etc/resolv.conf
                echo "------------------------"
                echo "1. 优化DNS地址 "
                echo "2. 恢复初始设置 "
                echo "------------------------"
                echo "0. 返回上一层 "
                echo "------------------------"
                echo ""
                # 询问用户是否要优化DNS设置
                read -p "请输入你的选择: " choice
                case "$choice" in
                    1)
                        set_dns
                        ;;
                    2)
                        # 重新启用systemd-resolved.service
                        rm -f /etc/resolv.conf
                        systemctl restart systemd-resolved.service
                        systemctl enable systemd-resolved.service
                        ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
                        ;;
                    0)
                        break
                        ;;
                    *)
                        echo "DNS设置未更改"
                        sleep 1s
                        ;;
                esac
            done
            ;;
          8)

          dd_xitong_2() {
            echo -e "任意键继续，重装后初始用户名: ${Yellow}root${White}  初始密码: ${Yellow}LeitboGi0ro${White}  初始端口: ${Yellow}22${White}"
            read -n 1 -s -r -p ""
            install wget
            wget --no-check-certificate -qO InstallNET.sh 'https://raw.githubusercontent.com/leitbogioro/Tools/master/Linux_reinstall/InstallNET.sh' && chmod a+x InstallNET.sh
          }

          dd_xitong_3() {
            echo -e "任意键继续，重装后初始用户名: ${Yellow}Administrator${White}  初始密码: ${Yellow}Teddysun.com${White}  初始端口: ${Yellow}3389${White}"
            read -n 1 -s -r -p ""
            install wget
            wget --no-check-certificate -qO InstallNET.sh 'https://raw.githubusercontent.com/leitbogioro/Tools/master/Linux_reinstall/InstallNET.sh' && chmod a+x InstallNET.sh
          }

          root_use
          echo "请备份数据，将为你重装系统，预计花费15分钟。"
          echo -e "${Gray}感谢MollyLau的脚本支持！${White} "
          read -p "确定继续吗？(Y/N): " choice

          case "$choice" in
            [Yy])
              while true; do

                echo "------------------------"
                echo "1. Debian 12"
                echo "2. Debian 11"
                echo "3. Debian 10"
                echo "4. Debian 9"
                echo "------------------------"
                echo "11. Ubuntu 24.04"
                echo "12. Ubuntu 22.04"
                echo "13. Ubuntu 20.04"
                echo "14. Ubuntu 18.04"
                echo "------------------------"
                echo "21. CentOS 9"
                echo "22. CentOS 8"
                echo "23. CentOS 7"
                echo "------------------------"
                echo "31. Alpine 3.19"
                echo "------------------------"
                echo "41. Windows 11"
                echo "42. Windows 10"
                echo "43. Windows Server 2022"
                echo "44. Windows Server 2019"
                echo "44. Windows Server 2016"
                echo "------------------------"
                read -p "请选择要重装的系统: " sys_choice

                case "$sys_choice" in
                  1)
                    dd_xitong_2
                    bash InstallNET.sh -debian 12
                    reboot
                    exit
                    ;;

                  2)
                    dd_xitong_2
                    bash InstallNET.sh -debian 11
                    reboot
                    exit
                    ;;

                  3)
                    dd_xitong_2
                    bash InstallNET.sh -debian 10
                    reboot
                    exit
                    ;;
                  4)
                    dd_xitong_2
                    bash InstallNET.sh -debian 9
                    reboot
                    exit
                    ;;

                  11)
                    dd_xitong_2
                    bash InstallNET.sh -ubuntu 24.04
                    reboot
                    exit
                    ;;
                  12)
                    dd_xitong_2
                    bash InstallNET.sh -ubuntu 22.04
                    reboot
                    exit
                    ;;

                  13)
                    dd_xitong_2
                    bash InstallNET.sh -ubuntu 20.04
                    reboot
                    exit
                    ;;
                  14)
                    dd_xitong_2
                    bash InstallNET.sh -ubuntu 18.04
                    reboot
                    exit
                    ;;


                  21)
                    dd_xitong_2
                    bash InstallNET.sh -centos 9
                    reboot
                    exit
                    ;;


                  22)
                    dd_xitong_2
                    bash InstallNET.sh -centos 8
                    reboot
                    exit
                    ;;

                  23)
                    dd_xitong_2
                    bash InstallNET.sh -centos 7
                    reboot
                    exit
                    ;;

                  31)
                    dd_xitong_2
                    bash InstallNET.sh -alpine
                    reboot
                    exit
                    ;;

                  41)
                    dd_xitong_3
                    bash InstallNET.sh -windows 11 -lang "cn"
                    reboot
                    exit
                    ;;

                  42)
                    dd_xitong_3
                    bash InstallNET.sh -windows 10 -lang "cn"
                    reboot
                    exit
                    ;;

                  43)
                    dd_xitong_3
                    bash InstallNET.sh -windows 2022 -lang "cn"
                    reboot
                    exit
                    ;;

                  44)
                    dd_xitong_3
                    bash InstallNET.sh -windows 2019 -lang "cn"
                    reboot
                    exit
                    ;;

                  45)
                    dd_xitong_3
                    bash InstallNET.sh -windows 2016 -lang "cn"
                    reboot
                    exit
                    ;;


                  *)
                    echo "无效的选择，请重新输入。"
                    ;;
                esac
              done
              ;;
            [Nn])
              echo "已取消"
              ;;
            *)
              echo "无效的选择，请输入 Y 或 N。"
              ;;
          esac
              ;;

          9)
            root_use

            # 提示用户输入新用户名
            read -p "请输入新用户名: " new_username

            # 创建新用户并设置密码
            useradd -m -s /bin/bash "$new_username"
            passwd "$new_username"

            # 赋予新用户sudo权限
            echo "$new_username ALL=(ALL:ALL) ALL" | sudo tee -a /etc/sudoers

            # 禁用ROOT用户登录
            passwd -l root

            echo "操作已完成。"
            ;;


          10)
          while true;do
                root_use
                ipv6_disabled=$(sysctl -n net.ipv6.conf.all.disable_ipv6)
                echo ""
                if [ "$ipv6_disabled" -eq 1 ]; then
                    echo "当前网络优先级设置: IPv4 优先"
                else
                    echo "当前网络优先级设置: IPv6 优先"
                fi

                result=$(curl -s --max-time 1 ipv6.ip.sb)
                if [ -n "$result" ]; then
                    echo "当前IPV6可用性: 可用"
                else
                    echo "当前IPV6可用性: 不可用"
                fi

                echo "------------------------"
                echo "切换的网络优先级"
                echo "------------------------"
                echo "1. IPv4 优先        2. IPv6 优先 "
                echo "3. 启用 IPv6        4. 禁用 IPv6 "
                echo "5. 还原 网络(IPv4/IPv6) 默认配置 "
                echo "6. 还原 IPv6(启用/禁用) 默认配置  "
                echo "------------------------"
                echo "0. 返回主菜单"
                echo "------------------------"
                read -p "选择优先的网络: " choice

                case $choice in
                    1)
                        sysctl -w net.ipv6.conf.all.disable_ipv6=1 > /dev/null 2>&1
                        restore_ip46
                        prefer_ipv4
                        echo "已切换为 IPv4 优先,可能需要重启！"
                        echo
                        ;;

                    2)
                        sysctl -w net.ipv6.conf.all.disable_ipv6=0 > /dev/null 2>&1
                        restore_ip46
                        prefer_ipv6
                        echo "已切换为 IPv6 优先,可能需要重启！"
                        echo
                        ;;
                        
                    3)
                        openipv6 > /dev/null 2>&1
                        restore_ipv6
                        enable_ipv6
                        echo "已启用 IPv6,可能需要重启！"
                        echo
                    ;;

                    4)
                        closeipv6 > /dev/null 2>&1
                        restore_ipv6
                        disable_ipv6
                        echo "已禁用 IPv6,可能需要重启！"
                        echo
                    ;;

                    5)
                        restore_ip46 'info'
                    ;;

                    6)
                        restore_ipv6 'info'
                    ;;

                    0)
                        back_main
                        ;;
                    *)
                        echo "无效的选择"
                        ;;

                esac
            done
          ;;
          11)
            clear
            ss -tulnape
            ;;

          12)
            root_use
            # 获取当前交换空间信息
            swap_used=$(free -m | awk 'NR==3{print $3}')
            swap_total=$(free -m | awk 'NR==3{print $2}')

            if [ "$swap_total" -eq 0 ]; then
              swap_percentage=0
            else
              swap_percentage=$((swap_used * 100 / swap_total))
            fi

            swap_info="${swap_used}MB/${swap_total}MB (${swap_percentage}%)"

            echo "当前虚拟内存: $swap_info"

            read -p "是否调整大小?(Y/N): " choice

            case "$choice" in
              [Yy])
                # 输入新的虚拟内存大小
                read -p "请输入虚拟内存大小MB: " new_swap
                add_swap

                ;;
              [Nn])
                echo "已取消"
                ;;
              *)
                echo "无效的选择，请输入 Y 或 N。"
                ;;
            esac
            ;;

          13)
              while true; do
                root_use

                # 显示所有用户、用户权限、用户组和是否在sudoers中
                echo "用户列表"
                echo "----------------------------------------------------------------------------"
                printf "%-24s %-34s %-20s %-10s\n" "用户名" "用户权限" "用户组" "sudo权限"
                while IFS=: read -r username _ userid groupid _ _ homedir shell; do
                    groups=$(groups "$username" | cut -d : -f 2)
                    sudo_status=$(sudo -n -lU "$username" 2>/dev/null | grep -q '(ALL : ALL)' && echo "Yes" || echo "No")
                    printf "%-20s %-30s %-20s %-10s\n" "$username" "$homedir" "$groups" "$sudo_status"
                done < /etc/passwd


                  echo ""
                  echo "账户操作"
                  echo "------------------------"
                  echo "1. 创建普通账户             2. 创建高级账户"
                  echo "------------------------"
                  echo "3. 赋予最高权限             4. 取消最高权限"
                  echo "------------------------"
                  echo "5. 删除账号"
                  echo "------------------------"
                  echo "0. 返回上一级选单"
                  echo "------------------------"
                  read -p "请输入你的选择: " sub_choice

                  case $sub_choice in
                      1)
                       # 提示用户输入新用户名
                       read -p "请输入新用户名: " new_username

                       # 创建新用户并设置密码
                       useradd -m -s /bin/bash "$new_username"
                       passwd "$new_username"

                       echo "操作已完成。"
                          ;;

                      2)
                       # 提示用户输入新用户名
                       read -p "请输入新用户名: " new_username

                       # 创建新用户并设置密码
                       useradd -m -s /bin/bash "$new_username"
                       passwd "$new_username"

                       # 赋予新用户sudo权限
                       echo "$new_username ALL=(ALL:ALL) ALL" | sudo tee -a /etc/sudoers

                       echo "操作已完成。"

                          ;;
                      3)
                       read -p "请输入用户名: " username
                       # 赋予新用户sudo权限
                       echo "$username ALL=(ALL:ALL) ALL" | sudo tee -a /etc/sudoers
                          ;;
                      4)
                       read -p "请输入用户名: " username
                       # 从sudoers文件中移除用户的sudo权限
                       sed -i "/^$username\sALL=(ALL:ALL)\sALL/d" /etc/sudoers

                          ;;
                      5)
                       read -p "请输入要删除的用户名: " username
                       # 删除用户及其主目录
                       userdel -r "$username"
                          ;;

                      0)
                          break  # 跳出循环，退出菜单
                          ;;

                      *)
                          break  # 跳出循环，退出菜单
                          ;;
                  esac
              done
              ;;

          14)
            clear

            echo "随机用户名"
            echo "------------------------"
            for i in {1..5}; do
                username="user$(< /dev/urandom tr -dc _a-z0-9 | head -c6)"
                echo "随机用户名 $i: $username"
            done

            echo ""
            echo "随机姓名"
            echo "------------------------"
            first_names=("John" "Jane" "Michael" "Emily" "David" "Sophia" "William" "Olivia" "James" "Emma" "Ava" "Liam" "Mia" "Noah" "Isabella")
            last_names=("Smith" "Johnson" "Brown" "Davis" "Wilson" "Miller" "Jones" "Garcia" "Martinez" "Williams" "Lee" "Gonzalez" "Rodriguez" "Hernandez")

            # 生成5个随机用户姓名
            for i in {1..5}; do
                first_name_index=$((RANDOM % ${#first_names[@]}))
                last_name_index=$((RANDOM % ${#last_names[@]}))
                user_name="${first_names[$first_name_index]} ${last_names[$last_name_index]}"
                echo "随机用户姓名 $i: $user_name"
            done

            echo ""
            echo "随机UUID"
            echo "------------------------"
            for i in {1..5}; do
                uuid=$(cat /proc/sys/kernel/random/uuid)
                echo "随机UUID $i: $uuid"
            done

            echo ""
            echo "16位随机密码"
            echo "------------------------"
            for i in {1..5}; do
                password=$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c16)
                echo "随机密码 $i: $password"
            done

            echo ""
            echo "32位随机密码"
            echo "------------------------"
            for i in {1..5}; do
                password=$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c32)
                echo "随机密码 $i: $password"
            done
            echo ""

              ;;

          15)
            root_use
            while true; do

                echo "系统时间信息"

                # 获取当前系统时区
                timezone=$(current_timezone)

                # 获取当前系统时间
                current_time=$(date +"%Y-%m-%d %H:%M:%S")

                # 显示时区和时间
                echo "当前系统时区：$timezone"
                echo "当前系统时间：$current_time"

                echo ""
                echo "时区切换"
                echo "亚洲------------------------"
                echo "1. 中国上海时间              2. 中国香港时间"
                echo "3. 日本东京时间              4. 韩国首尔时间"
                echo "5. 新加坡时间                6. 印度加尔各答时间"
                echo "7. 阿联酋迪拜时间            8. 澳大利亚悉尼时间"
                echo "欧洲------------------------"
                echo "11. 英国伦敦时间             12. 法国巴黎时间"
                echo "13. 德国柏林时间             14. 俄罗斯莫斯科时间"
                echo "15. 荷兰尤特赖赫特时间       16. 西班牙马德里时间"
                echo "美洲------------------------"
                echo "21. 美国西部时间             22. 美国东部时间"
                echo "23. 加拿大时间               24. 墨西哥时间"
                echo "25. 巴西时间                 26. 阿根廷时间"
                echo "------------------------"
                echo "0. 返回上一级选单"
                echo "------------------------"
                read -p "请输入你的选择: " sub_choice


                case $sub_choice in
                    1) set_timedate Asia/Shanghai ;;
                    2) set_timedate Asia/Hong_Kong ;;
                    3) set_timedate Asia/Tokyo ;;
                    4) set_timedate Asia/Seoul ;;
                    5) set_timedate Asia/Singapore ;;
                    6) set_timedate Asia/Kolkata ;;
                    7) set_timedate Asia/Dubai ;;
                    8) set_timedate Australia/Sydney ;;
                    11) set_timedate Europe/London ;;
                    12) set_timedate Europe/Paris ;;
                    13) set_timedate Europe/Berlin ;;
                    14) set_timedate Europe/Moscow ;;
                    15) set_timedate Europe/Amsterdam ;;
                    16) set_timedate Europe/Madrid ;;
                    21) set_timedate America/Los_Angeles ;;
                    22) set_timedate America/New_York ;;
                    23) set_timedate America/Vancouver ;;
                    24) set_timedate America/Mexico_City ;;
                    25) set_timedate America/Sao_Paulo ;;
                    26) set_timedate America/Argentina/Buenos_Aires ;;
                    0) break ;; # 跳出循环，退出菜单
                    *) break ;; # 跳出循环，退出菜单
                esac
            done
              ;;

          16)
          root_use
          if dpkg -l | grep -q 'linux-xanmod'; then
            while true; do

                  kernel_version=$(uname -r)
                  echo "您已安装xanmod的BBRv3内核"
                  echo "当前内核版本: $kernel_version"

                  echo ""
                  echo "内核管理"
                  echo "------------------------"
                  echo "1. 更新BBRv3内核              2. 卸载BBRv3内核"
                  echo "------------------------"
                  echo "0. 返回上一级选单"
                  echo "------------------------"
                  read -p "请输入你的选择: " sub_choice

                  case $sub_choice in
                      1)
                        apt purge -y 'linux-*xanmod1*'
                        update-grub

                        wget -qO - https://dl.xanmod.org/archive.key | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg --yes
                        #wget -qO - https://raw.githubusercontent.com/railzen/CherryScript/main/tools/cherry/config/archive.key | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg --yes

                        # 步骤3：添加存储库
                        echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | tee /etc/apt/sources.list.d/xanmod-release.list

                        version=$(wget -q https://dl.xanmod.org/check_x86-64_psabi.sh && chmod +x check_x86-64_psabi.sh && ./check_x86-64_psabi.sh | grep -oP 'x86-64-v\K\d+|x86-64-v\d+')
                        # version=$(wget -q https://raw.githubusercontent.com/railzen/CherryScript/main/tools/check_x86-64_psabi.sh && chmod +x check_x86-64_psabi.sh && ./check_x86-64_psabi.sh | grep -oP 'x86-64-v\K\d+|x86-64-v\d+')

                        apt update -y
                        apt install -y linux-xanmod-lts-x64v$version

                        echo "XanMod内核已更新。重启后生效"
                        rm -f /etc/apt/sources.list.d/xanmod-release.list
                        rm -f check_x86-64_psabi.sh*

                        server_reboot

                          ;;
                      2)
                        apt purge -y 'linux-*xanmod1*'
                        update-grub
                        echo "XanMod内核已卸载。重启后生效"
                        server_reboot
                          ;;
                      0)
                          break  # 跳出循环，退出菜单
                          ;;

                      *)
                          break  # 跳出循环，退出菜单
                          ;;

                  esac
            done
        else

          clear
          echo "请备份数据，将为你升级Linux内核开启BBR3"
          echo "官网介绍: https://xanmod.org/"
          echo "------------------------------------------------"
          echo "仅支持Debian/Ubuntu 仅支持x86_64架构"
          echo "VPS是512M内存的，将自动添加512M虚拟内存，防止因内存不足失联！"
          echo "------------------------------------------------"
          read -p "确定继续吗？(Y/N): " choice

          case "$choice" in
            [Yy])
            if [ -r /etc/os-release ]; then
                . /etc/os-release
                if [ "$ID" != "debian" ] && [ "$ID" != "ubuntu" ]; then
                    echo "当前环境不支持，仅支持Debian和Ubuntu系统"
                    break
                fi
            else
                echo "无法确定操作系统类型"
                break
            fi

            # 检查系统架构
            arch=$(dpkg --print-architecture)
            if [ "$arch" != "amd64" ]; then
              echo "当前环境不支持，仅支持x86_64架构"
              break
            fi

            new_swap=510
            add_swap
            install wget gnupg

            wget -qO - https://dl.xanmod.org/archive.key | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg --yes
            # wget -qO - https://raw.githubusercontent.com/railzen/CherryScript/main/tools/config/archive.key | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg --yes

            # 步骤3：添加存储库
            echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | tee /etc/apt/sources.list.d/xanmod-release.list

            version=$(wget -q https://dl.xanmod.org/check_x86-64_psabi.sh && chmod +x check_x86-64_psabi.sh && ./check_x86-64_psabi.sh | grep -oP 'x86-64-v\K\d+|x86-64-v\d+')
            # version=$(wget -q https://raw.githubusercontent.com/railzen/CherryScript/main/tools/check_x86-64_psabi.sh && chmod +x check_x86-64_psabi.sh && ./check_x86-64_psabi.sh | grep -oP 'x86-64-v\K\d+|x86-64-v\d+')

            apt update -y
            apt install -y linux-xanmod-x64v$version

            # 步骤5：启用BBR3
            cat > /etc/sysctl.conf << EOF
net.core.default_qdisc=fq_pie
net.ipv4.tcp_congestion_control=bbr
EOF
            sysctl -p
            echo "XanMod内核安装并BBR3启用成功。重启后生效"
            rm -f /etc/apt/sources.list.d/xanmod-release.list
            rm -f check_x86-64_psabi.sh*
            server_reboot

              ;;
            [Nn])
              echo "已取消"
              ;;
            *)
              echo "无效的选择，请输入 Y 或 N。"
              ;;
          esac
        fi
              ;;

          17)
          root_use
          if dpkg -l | grep -q iptables-persistent; then
            while true; do
                  echo "防火墙已安装"
                  echo "------------------------"
                  iptables -L INPUT

                  echo ""
                  echo "防火墙管理"
                  echo "------------------------"
                  echo "1. 开放指定端口              2. 关闭指定端口"
                  echo "3. 开放所有端口              4. 关闭所有端口"
                  echo "------------------------"
                  echo "5. IP白名单                  6. IP黑名单"
                  echo "7. 清除指定IP"
                  echo "------------------------"
                  echo "9. 卸载防火墙"
                  echo "------------------------"
                  echo "0. 返回上一级选单"
                  echo "------------------------"
                  read -p "请输入你的选择: " sub_choice

                  case $sub_choice in
                      1)
                      read -p "请输入开放的端口号: " o_port
                      sed -i "/COMMIT/i -A INPUT -p tcp --dport $o_port -j ACCEPT" /etc/iptables/rules.v4
                      sed -i "/COMMIT/i -A INPUT -p udp --dport $o_port -j ACCEPT" /etc/iptables/rules.v4
                      iptables-restore < /etc/iptables/rules.v4

                          ;;
                      2)
                      read -p "请输入关闭的端口号: " c_port
                      sed -i "/--dport $c_port/d" /etc/iptables/rules.v4
                      iptables-restore < /etc/iptables/rules.v4
                        ;;

                      3)
                      current_port=$(grep -E '^ *Port [0-9]+' /etc/ssh/sshd_config | awk '{print $2}')

                      cat > /etc/iptables/rules.v4 << EOF
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A FORWARD -i lo -j ACCEPT
-A INPUT -p tcp --dport $current_port -j ACCEPT
COMMIT
EOF
                      iptables-restore < /etc/iptables/rules.v4

                          ;;
                      4)
                      current_port=$(grep -E '^ *Port [0-9]+' /etc/ssh/sshd_config | awk '{print $2}')

                      cat > /etc/iptables/rules.v4 << EOF
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A FORWARD -i lo -j ACCEPT
-A INPUT -p tcp --dport $current_port -j ACCEPT
COMMIT
EOF
                      iptables-restore < /etc/iptables/rules.v4

                          ;;

                      5)
                      read -p "请输入放行的IP: " o_ip
                      sed -i "/COMMIT/i -A INPUT -s $o_ip -j ACCEPT" /etc/iptables/rules.v4
                      iptables-restore < /etc/iptables/rules.v4

                          ;;

                      6)
                      read -p "请输入封锁的IP: " c_ip
                      sed -i "/COMMIT/i -A INPUT -s $c_ip -j DROP" /etc/iptables/rules.v4
                      iptables-restore < /etc/iptables/rules.v4
                          ;;

                      7)
                     read -p "请输入清除的IP: " d_ip
                     sed -i "/-A INPUT -s $d_ip/d" /etc/iptables/rules.v4
                     iptables-restore < /etc/iptables/rules.v4
                          ;;

                      9)
                      remove iptables-persistent
                      rm /etc/iptables/rules.v4
                      break
                          ;;

                      0)
                          break  # 跳出循环，退出菜单
                          ;;

                      *)
                          break  # 跳出循环，退出菜单
                          ;;

                  esac
            done
        else

          clear
          echo "将为你安装防火墙，该防火墙仅支持Debian/Ubuntu"
          echo "------------------------------------------------"
          read -p "确定继续吗？(Y/N): " choice

          case "$choice" in
            [Yy])
            if [ -r /etc/os-release ]; then
                . /etc/os-release
                if [ "$ID" != "debian" ] && [ "$ID" != "ubuntu" ]; then
                    echo "当前环境不支持，仅支持Debian和Ubuntu系统"
                    break
                fi
            else
                echo "无法确定操作系统类型"
                break
            fi

          clear
          iptables_open
          remove iptables-persistent ufw
          rm /etc/iptables/rules.v4

          apt update -y && apt install -y iptables-persistent

          current_port=$(grep -E '^ *Port [0-9]+' /etc/ssh/sshd_config | awk '{print $2}')

          cat > /etc/iptables/rules.v4 << EOF
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A FORWARD -i lo -j ACCEPT
-A INPUT -p tcp --dport $current_port -j ACCEPT
COMMIT
EOF

          iptables-restore < /etc/iptables/rules.v4
          systemctl enable netfilter-persistent
          echo "防火墙安装完成"


              ;;
            [Nn])
              echo "已取消"
              ;;
            *)
              echo "无效的选择，请输入 Y 或 N。"
              ;;
          esac
        fi
              ;;

          18)
          root_use
          current_hostname=$(hostname)
          echo "当前主机名: $current_hostname"
          read -p "是否要更改主机名？(y/n): " answer
          if [[ "${answer}" == "y" ]]; then
              # 获取新的主机名
              read -p "请输入新的主机名: " new_hostname
              if [ -n "$new_hostname" ]; then
                  if [ -f /etc/alpine-release ]; then
                      # Alpine
                      echo "$new_hostname" > /etc/hostname
                      hostname "$new_hostname"
                  else
                      # 其他系统，如 Debian, Ubuntu, CentOS 等
                      hostnamectl set-hostname "$new_hostname"
                      sed -i "s/$current_hostname/$new_hostname/g" /etc/hostname
                      systemctl restart systemd-hostnamed
                  fi
                  echo "主机名已更改为: $new_hostname"
              else
                  echo "无效的主机名。未更改主机名。"
                  exit 1
              fi
          else
              echo "未更改主机名。"
          fi
              ;;

          19)
          root_use
          # 获取系统信息
          source /etc/os-release

          # 定义 Ubuntu 更新源
          aliyun_ubuntu_source="http://mirrors.aliyun.com/ubuntu/"
          official_ubuntu_source="http://archive.ubuntu.com/ubuntu/"
          initial_ubuntu_source=""

          # 定义 Debian 更新源
          aliyun_debian_source="http://mirrors.aliyun.com/debian/"
          official_debian_source="http://deb.debian.org/debian/"
          initial_debian_source=""

          # 定义 CentOS 更新源
          aliyun_centos_source="http://mirrors.aliyun.com/centos/"
          official_centos_source="http://mirror.centos.org/centos/"
          initial_centos_source=""

          # 获取当前更新源并设置初始源
          case "$ID" in
              ubuntu)
                  initial_ubuntu_source=$(grep -E '^deb ' /etc/apt/sources.list | head -n 1 | awk '{print $2}')
                  ;;
              debian)
                  initial_debian_source=$(grep -E '^deb ' /etc/apt/sources.list | head -n 1 | awk '{print $2}')
                  ;;
              centos)
                  initial_centos_source=$(awk -F= '/^baseurl=/ {print $2}' /etc/yum.repos.d/CentOS-Base.repo | head -n 1 | tr -d ' ')
                  ;;
              *)
                  echo "未知系统，无法执行切换源脚本"
                  exit 1
                  ;;
          esac

          # 备份当前源
          backup_sources() {
              case "$ID" in
                  ubuntu)
                      cp /etc/apt/sources.list /etc/apt/sources.list.bak
                      ;;
                  debian)
                      cp /etc/apt/sources.list /etc/apt/sources.list.bak
                      ;;
                  centos)
                      if [ ! -f /etc/yum.repos.d/CentOS-Base.repo.bak ]; then
                          cp /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.bak
                      else
                          echo "备份已存在，无需重复备份"
                      fi
                      ;;
                  *)
                      echo "未知系统，无法执行备份操作"
                      exit 1
                      ;;
              esac
              echo "已备份当前更新源为 /etc/apt/sources.list.bak 或 /etc/yum.repos.d/CentOS-Base.repo.bak"
          }

          # 还原初始更新源
          restore_initial_source() {
              case "$ID" in
                  ubuntu)
                      cp /etc/apt/sources.list.bak /etc/apt/sources.list
                      ;;
                  debian)
                      cp /etc/apt/sources.list.bak /etc/apt/sources.list
                      ;;
                  centos)
                      cp /etc/yum.repos.d/CentOS-Base.repo.bak /etc/yum.repos.d/CentOS-Base.repo
                      ;;
                  *)
                      echo "未知系统，无法执行还原操作"
                      exit 1
                      ;;
              esac
              echo "已还原初始更新源"
          }

          # 函数：切换更新源
          switch_source() {
              case "$ID" in
                  ubuntu)
                      sed -i 's|'"$initial_ubuntu_source"'|'"$1"'|g' /etc/apt/sources.list
                      ;;
                  debian)
                      sed -i 's|'"$initial_debian_source"'|'"$1"'|g' /etc/apt/sources.list
                      ;;
                  centos)
                      sed -i "s|^baseurl=.*$|baseurl=$1|g" /etc/yum.repos.d/CentOS-Base.repo
                      ;;
                  *)
                      echo "未知系统，无法执行切换操作"
                      exit 1
                      ;;
              esac
          }

          # 主菜单
          while true; do
              case "$ID" in
                  ubuntu)
                      echo "Ubuntu 更新源切换脚本"
                      echo "------------------------"
                      ;;
                  debian)
                      echo "Debian 更新源切换脚本"
                      echo "------------------------"
                      ;;
                  centos)
                      echo "CentOS 更新源切换脚本"
                      echo "------------------------"
                      ;;
                  *)
                      echo "未知系统，无法执行脚本"
                      exit 1
                      ;;
              esac

              echo "1. 切换到阿里云源"
              echo "2. 切换到官方源"
              echo "------------------------"
              echo "3. 备份当前更新源"
              echo "4. 还原初始更新源"
              echo "------------------------"
              echo "0. 返回上一级"
              echo "------------------------"
              read -p "请选择操作: " choice

              case $choice in
                  1)
                      backup_sources
                      case "$ID" in
                          ubuntu)
                              switch_source $aliyun_ubuntu_source
                              ;;
                          debian)
                              switch_source $aliyun_debian_source
                              ;;
                          centos)
                              switch_source $aliyun_centos_source
                              ;;
                          *)
                              echo "未知系统，无法执行切换操作"
                              exit 1
                              ;;
                      esac
                      echo "已切换到阿里云源"
                      ;;
                  2)
                      backup_sources
                      case "$ID" in
                          ubuntu)
                              switch_source $official_ubuntu_source
                              ;;
                          debian)
                              switch_source $official_debian_source
                              ;;
                          centos)
                              switch_source $official_centos_source
                              ;;
                          *)
                              echo "未知系统，无法执行切换操作"
                              exit 1
                              ;;
                      esac
                      echo "已切换到官方源"
                      ;;
                  3)
                      backup_sources
                      case "$ID" in
                          ubuntu)
                              switch_source $initial_ubuntu_source
                              ;;
                          debian)
                              switch_source $initial_debian_source
                              ;;
                          centos)
                              switch_source $initial_centos_source
                              ;;
                          *)
                              echo "未知系统，无法执行切换操作"
                              exit 1
                              ;;
                      esac
                      echo "已切换到初始更新源"
                      ;;
                  4)
                      restore_initial_source
                      ;;
                  0)
                      break
                      ;;
                  *)
                      echo "无效的选择，请重新输入"
                      ;;
              esac
              break_end

          done

              ;;

          20)
          while true; do
              clear
              echo "定时任务列表"
              crontab -l
              echo ""
              echo "操作"
              echo "------------------------"
              echo "1. 添加定时任务              2. 删除定时任务              3. 编辑定时任务"
              echo "------------------------"
              echo "0. 返回上一级选单"
              echo "------------------------"
              read -p "请输入你的选择: " sub_choice

              case $sub_choice in
                  1)
                      read -p "请输入新任务的执行命令: " newquest
                      echo "------------------------"
                      echo "1. 每月任务                 2. 每周任务"
                      echo "3. 每天任务                 4. 每小时任务"
                      echo "------------------------"
                      read -p "请输入你的选择: " dingshi

                      case $dingshi in
                          1)
                              read -p "选择每月的几号执行任务？ (1-30): " day
                              (crontab -l ; echo "0 0 $day * * $newquest") | crontab - > /dev/null 2>&1
                              ;;
                          2)
                              read -p "选择周几执行任务？ (0-6，0代表星期日): " weekday
                              (crontab -l ; echo "0 0 * * $weekday $newquest") | crontab - > /dev/null 2>&1
                              ;;
                          3)
                              read -p "选择每天几点执行任务？（小时，0-23）: " hour
                              (crontab -l ; echo "0 $hour * * * $newquest") | crontab - > /dev/null 2>&1
                              ;;
                          4)
                              read -p "输入每小时的第几分钟执行任务？（分钟，0-60）: " minute
                              (crontab -l ; echo "$minute * * * * $newquest") | crontab - > /dev/null 2>&1
                              ;;
                          *)
                              break  # 跳出
                              ;;
                      esac
                      ;;
                  2)
                      read -p "请输入需要删除任务的关键字: " kquest
                      crontab -l | grep -v "$kquest" | crontab -
                      ;;
                  3)
                      crontab -e
                      ;;
                  0)
                      break  # 跳出循环，退出菜单
                      ;;

                  *)
                      break  # 跳出循环，退出菜单
                      ;;
              esac
          done

          ;;


          21)
              root_use
              while true; do
                  echo "本机host解析列表"
                  echo "如果你在这里添加解析匹配，将不再使用动态解析了"
                  cat /etc/hosts
                  echo ""
                  echo "操作"
                  echo "------------------------"
                  echo "1. 添加新的解析              2. 删除解析地址"
                  echo "------------------------"
                  echo "0. 返回上一级选单"
                  echo "------------------------"
                  read -p "请输入你的选择: " host_dns

                  case $host_dns in
                      1)
                          read -p "请输入新的解析记录 格式: 1.1.1.1 hostname.com : " addhost
                          echo "$addhost" >> /etc/hosts

                          ;;
                      2)
                          read -p "请输入需要删除的解析内容关键字: " delhost
                          sed -i "/$delhost/d" /etc/hosts
                          ;;
                      0)
                          break  # 跳出循环，退出菜单
                          ;;

                      *)
                          break  # 跳出循环，退出菜单
                          ;;
                  esac
              done
              ;;

          22)
            root_use
            if docker inspect fail2ban &>/dev/null ; then
                while true; do
                    clear
                    echo "SSH防御程序已启动"
                    echo "------------------------"
                    echo "1. 查看SSH拦截记录"
                    echo "2. 日志实时监控"
                    echo "------------------------"
                    echo "9. 卸载防御程序"
                    echo "------------------------"
                    echo "0. 退出"
                    echo "------------------------"
                    read -p "请输入你的选择: " sub_choice
                    case $sub_choice in

                        1)
                            echo "------------------------"
                            f2b_sshd
                            echo "------------------------"
                            ;;
                        2)
                            tail -f /path/to/fail2ban/config/log/fail2ban/fail2ban.log
                            break
                            ;;
                        9)
                            docker rm -f fail2ban
                            rm -rf /path/to/fail2ban
                            echo "Fail2Ban防御程序已卸载"

                            break
                            ;;
                        0)
                            break
                            ;;
                        *)
                            echo "无效的选择，请重新输入。"
                            ;;
                    esac
                    break_end

                done

            elif [ -x "$(command -v fail2ban-client)" ] ; then
                clear
                echo "卸载旧版fail2ban"
                read -p "确定继续吗？(Y/N): " choice
                case "$choice" in
                  [Yy])
                    remove fail2ban
                    rm -rf /etc/fail2ban
                    echo "Fail2Ban防御程序已卸载"
                    ;;
                  [Nn])
                    echo "已取消"
                    ;;
                  *)
                    echo "无效的选择，请输入 Y 或 N。"
                    ;;
                esac

            else

              clear
              echo "fail2ban是一个SSH防止暴力破解工具"
              echo "官网介绍: https://github.com/fail2ban/fail2ban"
              echo "------------------------------------------------"
              echo "工作原理：研判非法IP恶意高频访问SSH端口，自动进行IP封锁"
              echo "------------------------------------------------"
              read -p "确定继续吗？(Y/N): " choice

              case "$choice" in
                [Yy])
                  clear
                  install_docker
                  f2b_install_sshd

                  cd ~
                  f2b_status
                  echo "Fail2Ban防御程序已开启"

                  ;;
                [Nn])
                  echo "已取消"
                  ;;
                *)
                  echo "无效的选择，请输入 Y 或 N。"
                  ;;
              esac
            fi
              ;;


          23)
            root_use
            echo "当前流量使用情况，重启服务器流量计算会清零！"
            output_status
            echo "$output"

            # 检查是否存在 Limiting_Shut_down.sh 文件
            if [ -f ~/Limiting_Shut_down.sh ]; then
                # 获取 threshold_gb 的值
                threshold_gb=$(grep -oP 'threshold_gb=\K\d+' ~/Limiting_Shut_down.sh)
                echo -e "当前设置的限流阈值为 ${hang}${threshold_gb}${White}GB"
            else
                echo -e "${Gray}前未启用限流关机功能${White}"
            fi

            echo
            echo "------------------------------------------------"
            echo "系统每分钟会检测实际流量是否到达阈值，到达后会自动关闭服务器！每月1日重置流量重启服务器。"
            read -p "1. 开启限流关机功能    2. 停用限流关机功能    0. 退出  : " Limiting

            case "$Limiting" in
              1)
                # 输入新的虚拟内存大小
                echo "如果实际服务器就100G流量，可设置阈值为95G，提前关机，以免出现流量误差或溢出."
                read -p "请输入流量阈值（单位为GB）: " threshold_gb
                cd ~
                curl -Ss -O https://raw.githubusercontent.com/railzen/CherryScript/main/tools/Limiting_Shut_down.sh
                chmod +x ~/Limiting_Shut_down.sh
                sed -i "s/110/$threshold_gb/g" ~/Limiting_Shut_down.sh
                crontab -l | grep -v '~/Limiting_Shut_down.sh' | crontab -
                (crontab -l ; echo "* * * * * ~/Limiting_Shut_down.sh") | crontab - > /dev/null 2>&1
                crontab -l | grep -v 'reboot' | crontab -
                (crontab -l ; echo "0 1 1 * * reboot") | crontab - > /dev/null 2>&1
                echo "限流关机已设置"

                ;;
              0)
                echo "已取消"
                ;;
              2)
                crontab -l | grep -v '~/Limiting_Shut_down.sh' | crontab -
                crontab -l | grep -v 'reboot' | crontab -
                rm ~/Limiting_Shut_down.sh
                echo "已关闭限流关机功能"
                ;;
              *)
                echo "无效的选择，请输入 Y 或 N。"
                ;;
            esac

              ;;


          24)
            root_use
            # 系统检测
            OS=$(cat /etc/os-release | grep -o -E "Debian|Ubuntu|CentOS" | head -n 1)

            if [[ $OS == "Debian" || $OS == "Ubuntu" || $OS == "CentOS" ]]; then
                echo -e "检测到你的系统是 ${Yellow}${OS}${White}"
            else
                echo -e "${Red}很抱歉，你的系统不受支持！${White}"
                exit 1
            fi

            # 检测安装Python3的版本
            VERSION=$(python3 -V 2>&1 | awk '{print $2}')

            # 获取最新Python3版本
            PY_VERSION=$(curl -s https://www.python.org/ | grep "downloads/release" | grep -o 'Python [0-9.]*' | grep -o '[0-9.]*')

            # 卸载Python3旧版本
            if [[ $VERSION == "3"* ]]; then
                echo -e "${Yellow}你的Python3版本是${White}${Red}${VERSION}${White}，${Yellow}最新版本是${White}${Red}${PY_VERSION}${White}"
                read -p "是否确认升级最新版Python3？默认不升级 [y/N]: " CONFIRM
                if [[ $CONFIRM == "y" ]]; then
                    if [[ $OS == "CentOS" ]]; then
                        echo ""
                        rm-rf /usr/local/python3* >/dev/null 2>&1
                    else
                        apt --purge remove python3 python3-pip -y
                        rm-rf /usr/local/python3*
                    fi
                else
                    echo -e "${Yellow}已取消升级Python3${White}"
                    exit 1
                fi
            else
                echo -e "${Red}检测到没有安装Python3。${White}"
                read -p "是否确认安装最新版Python3？默认安装 [Y/n]: " CONFIRM
                if [[ $CONFIRM != "n" ]]; then
                    echo -e "${Green}开始安装最新版Python3...${White}"
                else
                    echo -e "${Yellow}已取消安装Python3${White}"
                    exit 1
                fi
            fi

            # 安装相关依赖
            if [[ $OS == "CentOS" ]]; then
                yum update
                yum groupinstall -y "development tools"
                yum install wget openssl-devel bzip2-devel libffi-devel zlib-devel -y
            else
                apt update
                apt install wget build-essential libreadline-dev libncursesw5-dev libssl-dev libsqlite3-dev tk-dev libgdbm-dev libc6-dev libbz2-dev libffi-dev zlib1g-dev -y
            fi

            # 安装python3
            cd /root/
            wget https://www.python.org/ftp/python/${PY_VERSION}/Python-"$PY_VERSION".tgz
            tar -zxf Python-${PY_VERSION}.tgz
            cd Python-${PY_VERSION}
            ./configure --prefix=/usr/local/python3
            make -j $(nproc)
            make install
            if [ $? -eq 0 ];then
                rm -f /usr/local/bin/python3*
                rm -f /usr/local/bin/pip3*
                ln -sf /usr/local/python3/bin/python3 /usr/bin/python3
                ln -sf /usr/local/python3/bin/pip3 /usr/bin/pip3
                clear
                echo -e "${Yellow}Python3安装${Green}成功，${White}版本为: ${White}${Green}${PY_VERSION}${White}"
            else
                clear
                echo -e "${Red}Python3安装失败！${White}"
                exit 1
            fi
            cd /root/ && rm -rf Python-${PY_VERSION}.tgz && rm -rf Python-${PY_VERSION}
            ;;

          25)
              root_use
              echo "添加开机启动项"
              echo "------------------------------------------------"
              echo "将会生成一个系统服务以启动开机启动项，可在[${work_path}/config/start.sh]修改，请问是否要新增？"

              read -p "确定继续吗？(Y/N): " choice
              case "$choice" in
                [Yy])
                    mkdir -p ${work_path}/config
                    if [ ! -f "${work_path}/config/start.sh" ];then
                        echo "#!/usr/bin/env bash" > ${work_path}/config/start.sh
                    fi
                    
                    chmod +x ${work_path}/config/start.sh
                    echo '
[Unit]
Description= Cherry-startup
After=network-online.target
Wants=network-online.target systemd-networkd-wait-online.service
[Service]
LimitNOFILE=32767 
Type=simple
User=root
Restart=on-failure
RestartSec=5s
ExecStartPre=/bin/sh -c 'ulimit -n 51200'
ExecStart=/opt/CherryScript/config/start.sh
[Install]
WantedBy=multi-user.target' > /etc/systemd/system/Cherry-startup.service
                    systemctl enable --now Cherry-startup
                  ;;
                [Nn])
                  echo "已取消"
                  ;;
                *)
                  echo "无效的选择，请输入 Y 或 N。"
                  ;;
              esac

              ;;
          26)
            clear
            curl -sS -O https://raw.githubusercontent.com/railzen/CherryScript/main/tools/tcptools.sh && chmod +x tcptools.sh && ./tcptools.sh
            ;;

          27)
            [[ -z $(cat /usr/lib/systemd/system/systemd-networkd-wait-online.service | grep TimeoutStartSec) ]] && sed -i "s/RemainAfterExit=yes/RemainAfterExit=yes\nTimeoutStartSec=2sec/g" /usr/lib/systemd/system/systemd-networkd-wait-online.service && echo "成功将systemd-networkd-wait-online.service服务添加超时时间，TimeoutStartSec=2sec"
            ;;

          99)
              clear
              server_reboot
              ;;
          0)
              back_main

              ;;
          *)
              echo "无效的输入!"
              ;;    
              
      esac
      break_end

    done
    ;;

  11)
    #询问用户是否要安装Snell
        #read -p "是否要进入Snell V4安装脚本？(y/n): " choice
        #choice=y
        #if [ "$choice" == "y" ]; then
    clear
    bash -c "$(curl -sL https://raw.githubusercontent.com/railzen/CherryScript/main/snell/snell.sh)"
    ;;

  12)
    clear
    curl -sS -O https://raw.githubusercontent.com/railzen/CherryScript/main/proxy/setup_hysteria.sh && chmod +x setup_hysteria.sh && ./setup_hysteria.sh
    ;;

  13)
    clear
    curl -sS -O https://raw.githubusercontent.com/railzen/CherryScript/main/proxy/sing_box.sh && chmod +x sing_box.sh && ./sing_box.sh
    ;;

 99)
    Update_Shell
    ;;

  0)
    clear
    exit
    ;;

  *)
    echo "无效的输入!"
    ;;
esac
    break_end
done
}
# 从这里开始是IPV6优先级的函数部分[TAG279]

reload_sysctl() { sysctl -q -p && sysctl -q --system; }
restart_network() {
  echo -e "${Blue}正在重启网络服务...${White}"
  # NetworkManager
  if systemctl is-active --quiet NetworkManager; then systemctl restart NetworkManager
  # NetworkManager
  # elif command -v nmcli >/dev/null 2>&1; then nmcli networking off && nmcli networking on
  # CentOS/RedHat
  elif systemctl is-active --quiet network; then systemctl restart network
  # Debian/Ubuntu
  elif systemctl is-active --quiet networking; then systemctl restart networking
  else echo -e "${Yellow}无法重启网络服务, 请手动重启${White}"
  fi
}

# = prefer IPv4/IPv6
restore_ip46() {
  if [[ -f $GAICONF ]]; then
    sed -i "/$MARK/d" $GAICONF
  fi
  if [[ "$@" = 'info' ]]; then echo -e "${Green}已还原为默认配置${White}"; fi
}
prefer_ipv4() {
  echo "precedence ::ffff:0:0/96  100 $MARK" >>$GAICONF
}
prefer_ipv6() {
  echo "label 2002::/16   2 $MARK" >>$GAICONF
}


# = enable/disable IPv6
restore_ipv6() {
  sed -i "/$MARK/d" $SYSCTLCONF
  if [[ "$@" = 'info' ]]; then reload_sysctl;restart_network;echo -e "${Green}已还原为默认配置${White}"; fi
}
interfaces=("all" "default");
# interfaces+=$(ls /sys/class/net | grep -E '^(eth.*|lo)$')
# for interface in "${interfaces[@]}"; do echo $interface; done;
enable_ipv6() {
  for interface in "${interfaces[@]}"; do
    echo "net.ipv6.conf.${interface}.disable_ipv6=0 $MARK" >>$SYSCTLCONF
  done;
  reload_sysctl
  restart_network
}
disable_ipv6() {
  for interface in "${interfaces[@]}"; do
    echo "net.ipv6.conf.${interface}.disable_ipv6=1 $MARK" >>$SYSCTLCONF
  done;
  reload_sysctl
}

# 结束IPV6优先级的函数部分[/TAG279]
Update_Shell(){
	echo -e "当前版本为 ${main_version} ，开始检测最新版本..."
	sh_new_ver=$(curl -s "https://raw.githubusercontent.com/railzen/CherryScript/main/ludo.sh"|grep 'main_version="'|awk -F "=" '{print $NF}'|sed 's/\"//g'|head -1)
	[[ -z ${sh_new_ver} ]] && echo -e "${Error} 检测最新版本失败 !" && break_end
	if [[ ${sh_new_ver} != ${main_version} ]]; then
		read -p "发现新版本 ${sh_new_ver} ，是否更新？[Y/n] " yn
		[[ -z "${yn}" ]] && yn="y"
		if [[ ${yn} == [Yy] ]]; then
            cd ${work_path}/
            curl -sS -O https://raw.githubusercontent.com/railzen/CherryScript/main/ludo.sh && chmod +x ludo.sh
            rm -f /usr/local/bin/ludo
            cp -f ${work_path}/ludo.sh /usr/local/bin/ludo > /dev/null 2>&1
            echo ""
			echo -e "已更新版本 ${sh_new_ver} ! "
            break_end
            back_main
		else
			echo && echo "更新取消" && echo
            break_end
            back_main
		fi
	else
		echo -e "当前已是最新版本 ${sh_new_ver} !"
            break_end
            back_main
	fi
	break_end
    back_main
}

ip_address() {
ipv4_address=$(curl -s ipv4.ip.sb)
ipv6_address=$(curl -s --max-time 1 ipv6.ip.sb)
}

open_firewall_port() {
    ufw allow $1 > /dev/null 2>&1
    firewall-cmd --permanent --add-port=$1 > /dev/null 2>&1
    sed -i "/COMMIT/i -A INPUT -p tcp --dport $1 -j ACCEPT" /etc/iptables/rules.v4 > /dev/null 2>&1
    sed -i "/COMMIT/i -A INPUT -p udp --dport $1 -j ACCEPT" /etc/iptables/rules.v4 > /dev/null 2>&1
    iptables-restore < /etc/iptables/rules.v4 > /dev/null 2>&1
}

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


install_dependency() {
      clear
      install wget socat unzip tar
}


remove() {
    if [ $# -eq 0 ]; then
        echo "未提供软件包参数!"
        return 1
    fi

    for package in "$@"; do
        if command -v dnf &>/dev/null; then
            dnf remove -y "${package}*"
        elif command -v yum &>/dev/null; then
            yum remove -y "${package}*"
        elif command -v apt &>/dev/null; then
            apt purge -y "${package}*"
        elif command -v apk &>/dev/null; then
            apk del "${package}*"
        else
            echo "未知的包管理器!"
            return 1
        fi
    done

    return 0
}


break_end() {
      echo -e "${Green}操作完成${White}"
      echo "按任意键继续..."
      read -n 1 -s -r -p ""
      echo ""
      clear
}

back_main() {
            ludo
            exit
}

#禁用IPv6
closeipv6() {
  clear
  sed -i '/net.ipv6.conf.all.disable_ipv6/d' /etc/sysctl.d/99-sysctl.conf
  sed -i '/net.ipv6.conf.default.disable_ipv6/d' /etc/sysctl.d/99-sysctl.conf
  sed -i '/net.ipv6.conf.lo.disable_ipv6/d' /etc/sysctl.d/99-sysctl.conf
  sed -i '/net.ipv6.conf.all.disable_ipv6/d' /etc/sysctl.conf
  sed -i '/net.ipv6.conf.default.disable_ipv6/d' /etc/sysctl.conf
  sed -i '/net.ipv6.conf.lo.disable_ipv6/d' /etc/sysctl.conf

  echo "net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1" >>/etc/sysctl.d/99-sysctl.conf
  sysctl --system
#  echo -e "${Info}禁用IPv6结束，可能需要重启！"
}

#开启IPv6
openipv6() {
  clear
  sed -i '/net.ipv6.conf.all.disable_ipv6/d' /etc/sysctl.d/99-sysctl.conf
  sed -i '/net.ipv6.conf.default.disable_ipv6/d' /etc/sysctl.d/99-sysctl.conf
  sed -i '/net.ipv6.conf.lo.disable_ipv6/d' /etc/sysctl.d/99-sysctl.conf
  sed -i '/net.ipv6.conf.all.disable_ipv6/d' /etc/sysctl.conf
  sed -i '/net.ipv6.conf.default.disable_ipv6/d' /etc/sysctl.conf
  sed -i '/net.ipv6.conf.lo.disable_ipv6/d' /etc/sysctl.conf
  sed -i '/net.ipv6.conf.all.accept_ra/d' /etc/sysctl.conf
  sed -i '/net.ipv6.conf.default.accept_ra/d' /etc/sysctl.conf

  echo "net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
net.ipv6.conf.lo.disable_ipv6 = 0
net.ipv6.conf.all.accept_ra = 2
net.ipv6.conf.default.accept_ra = 2" >>/etc/sysctl.d/99-sysctl.conf
  sysctl --system
#  echo -e "${Info}开启IPv6结束，可能需要重启！"
}

check_port() {
    # 定义要检测的端口
    PORT=443

    # 检查端口占用情况
    result=$(ss -tulpn | grep ":$PORT")

    # 判断结果并输出相应信息
    if [ -n "$result" ]; then
        is_nginx_container=$(docker ps --format '{{.Names}}' | grep 'nginx')

        # 判断是否是Nginx容器占用端口
        if [ -n "$is_nginx_container" ]; then
            echo ""
        else
            clear
            echo -e "${Red}端口 ${Yellow}$PORT${Red} 已被占用，无法安装环境，卸载以下程序后重试！${White}"
            echo "$result"
            break_end
            back_main

        fi
    else
        echo ""
    fi
}

install_add_docker() {
    if [ -f "/etc/alpine-release" ]; then
        apk update
        apk add docker docker-compose
        rc-update add docker default
        service docker start
    else
        curl -fsSL https://get.docker.com | sh && ln -s /usr/libexec/docker/cli-plugins/docker-compose /usr/local/bin
        systemctl start docker
        systemctl enable docker
    fi

    sleep 2
}


install_docker() {
    if ! command -v docker &>/dev/null || ! command -v docker-compose &>/dev/null; then
        install_add_docker
    else
        echo "Docker环境已经安装"
    fi
}



iptables_open() {
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -F

    ip6tables -P INPUT ACCEPT
    ip6tables -P FORWARD ACCEPT
    ip6tables -P OUTPUT ACCEPT
    ip6tables -F

}



add_swap() {
    # 获取当前系统中所有的 swap 分区
    swap_partitions=$(grep -E '^/dev/' /proc/swaps | awk '{print $1}')

    # 遍历并删除所有的 swap 分区
    for partition in $swap_partitions; do
      swapoff "$partition"
      wipefs -a "$partition"  # 清除文件系统标识符
      mkswap -f "$partition"
    done

    # 确保 /swapfile 不再被使用
    swapoff /swapfile

    # 删除旧的 /swapfile
    rm -f /swapfile

    # 创建新的 swap 分区
    dd if=/dev/zero of=/swapfile bs=1M count=$new_swap
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile

    if [ -f /etc/alpine-release ]; then
        echo "/swapfile swap swap defaults 0 0" >> /etc/fstab
        echo "nohup swapon /swapfile" >> /etc/local.d/swap.start
        chmod +x /etc/local.d/swap.start
        rc-update add local
    else
        echo "/swapfile swap swap defaults 0 0" >> /etc/fstab
    fi

    echo -e "虚拟内存大小已调整为${Yellow}${new_swap}${White}MB"
}


install_certbot() {
    install certbot

    # 切换到一个一致的目录（例如，家目录）
    cd ~ || exit

    # 下载并使脚本可执行
    curl -O https://raw.githubusercontent.com/railzen/CherryScript/main/tools/auto_cert_renewal.sh
    chmod +x auto_cert_renewal.sh

    # 设置定时任务字符串
    cron_job="0 0 * * * ~/auto_cert_renewal.sh"

    # 检查是否存在相同的定时任务
    existing_cron=$(crontab -l 2>/dev/null | grep -F "$cron_job")

    # 如果不存在，则添加定时任务
    if [ -z "$existing_cron" ]; then
        (crontab -l 2>/dev/null; echo "$cron_job") | crontab -
        echo "续签任务已添加"
    else
        echo "续签任务已存在，无需添加"
    fi
}

install_ssltls() {
      docker stop nginx > /dev/null 2>&1
      #iptables_open
      cd ~
      certbot certonly --standalone -d $yuming --email your@email.com --agree-tos --no-eff-email --force-renewal
      cp /etc/letsencrypt/live/$yuming/fullchain.pem /home/web/certs/${yuming}_cert.pem
      cp /etc/letsencrypt/live/$yuming/privkey.pem /home/web/certs/${yuming}_key.pem
      docker start nginx > /dev/null 2>&1
}


default_server_ssl() {
install openssl
openssl req -x509 -nodes -newkey rsa:2048 -keyout /home/web/certs/default_server.key -out /home/web/certs/default_server.crt -days 5475 -subj "/C=US/ST=State/L=City/O=Organization/OU=Organizational Unit/CN=Common Name"

}

add_yuming() {
      ip_address
      echo -e "先将域名解析到本机IP: ${Yellow}$ipv4_address  $ipv6_address${White}"
      read -p "请输入你解析的域名: " yuming
}


docker_app() {
if docker inspect "$docker_name" &>/dev/null; then
    clear
    echo "$docker_name 已安装，访问地址: "
    ip_address
    echo "http:$ipv4_address:$docker_port"
    echo ""
    echo "应用操作"
    echo "------------------------"
    echo "1. 更新应用             2. 卸载应用"
    echo "------------------------"
    echo "0. 返回上一级选单"
    echo "------------------------"
    read -p "请输入你的选择: " sub_choice

    case $sub_choice in
        1)
            clear
            docker rm -f "$docker_name"
            docker rmi -f "$docker_img"

            $docker_rum
            clear
            echo "$docker_name 已经安装完成"
            echo "------------------------"
            # 获取外部 IP 地址
            ip_address
            echo "您可以使用以下地址访问:"
            echo "http:$ipv4_address:$docker_port"
            $docker_use
            $docker_passwd
            ;;
        2)
            clear
            docker rm -f "$docker_name"
            docker rmi -f "$docker_img"
            rm -rf "/home/docker/$docker_name"
            echo "应用已卸载"
            ;;
        0)
            # 跳出循环，退出菜单
            ;;
        *)
            # 跳出循环，退出菜单
            ;;
    esac
else
    clear
    echo "安装提示"
    echo "$docker_describe"
    echo "$docker_url"
    echo ""

    # 提示用户确认安装
    read -p "确定安装吗？(Y/N): " choice
    case "$choice" in
        [Yy])
            clear
            # 安装 Docker（请确保有 install_docker 函数）
            install_docker
            $docker_rum
            clear
            echo "$docker_name 已经安装完成"
            echo "------------------------"
            # 获取外部 IP 地址
            ip_address
            echo "您可以使用以下地址访问:"
            echo "http:$ipv4_address:$docker_port"
            $docker_use
            $docker_passwd
            ;;
        [Nn])
            # 用户选择不安装
            ;;
        *)
            # 无效输入
            ;;
    esac
fi

}


f2b_status() {
     docker restart fail2ban
     sleep 3
     docker exec -it fail2ban fail2ban-client status
}

f2b_status_xxx() {
    docker exec -it fail2ban fail2ban-client status $xxx
}

f2b_install_sshd() {

    docker run -d \
        --name=fail2ban \
        --net=host \
        --cap-add=NET_ADMIN \
        --cap-add=NET_RAW \
        -e PUID=1000 \
        -e PGID=1000 \
        -e TZ=Etc/UTC \
        -e VERBOSITY=-vv \
        -v /path/to/fail2ban/config:/config \
        -v /var/log:/var/log:ro \
        -v /home/web/log/nginx/:/remotelogs/nginx:ro \
        --restart unless-stopped \
        lscr.io/linuxserver/fail2ban:latest

    sleep 3
    if grep -q 'Alpine' /etc/issue; then
        cd /path/to/fail2ban/config/fail2ban/filter.d
        
        curl -sS -O https://raw.githubusercontent.com/railzen/CherryScript/main/tools/config/fail2ban/alpine-sshd.conf
        curl -sS -O https://raw.githubusercontent.com/railzen/CherryScript/main/tools/config/fail2ban/alpine-sshd-ddos.conf
        cd /path/to/fail2ban/config/fail2ban/jail.d/
        curl -sS -O https://raw.githubusercontent.com/railzen/CherryScript/main/tools/config/fail2ban/alpine-ssh.conf
    elif grep -qi 'CentOS' /etc/redhat-release; then
        cd /path/to/fail2ban/config/fail2ban/jail.d/
        curl -sS -O https://raw.githubusercontent.com/railzen/CherryScript/main/tools/config/fail2ban/centos-ssh.conf
    else
        install rsyslog
        systemctl start rsyslog
        systemctl enable rsyslog
        cd /path/to/fail2ban/config/fail2ban/jail.d/
        curl -sS -O https://raw.githubusercontent.com/railzen/CherryScript/main/tools/config/fail2ban/linux-ssh.conf
    fi
}

f2b_sshd() {
    if grep -q 'Alpine' /etc/issue; then
        xxx=alpine-sshd
        f2b_status_xxx
    elif grep -qi 'CentOS' /etc/redhat-release; then
        xxx=centos-sshd
        f2b_status_xxx
    else
        xxx=linux-sshd
        f2b_status_xxx
    fi
}






server_reboot() {

    read -p "$(echo -e "${Yellow}现在重启服务器吗？(Y/N): ${White}")" rboot
    case "$rboot" in
      [Yy])
        echo "已重启"
        reboot
        ;;
      [Nn])
        echo "已取消"
        ;;
      *)
        echo "无效的选择，请输入 Y 或 N。"
        ;;
    esac


}

output_status() {
    output=$(awk 'BEGIN { rx_total = 0; tx_total = 0 }
        NR > 2 { rx_total += $2; tx_total += $10 }
        END {
            rx_units = "Bytes";
            tx_units = "Bytes";
            if (rx_total > 1024) { rx_total /= 1024; rx_units = "KB"; }
            if (rx_total > 1024) { rx_total /= 1024; rx_units = "MB"; }
            if (rx_total > 1024) { rx_total /= 1024; rx_units = "GB"; }

            if (tx_total > 1024) { tx_total /= 1024; tx_units = "KB"; }
            if (tx_total > 1024) { tx_total /= 1024; tx_units = "MB"; }
            if (tx_total > 1024) { tx_total /= 1024; tx_units = "GB"; }

            printf("总接收: %.2f %s\n总发送: %.2f %s\n", rx_total, rx_units, tx_total, tx_units);
        }' /proc/net/dev)

}


install_panel() {
            if $lujing ; then
                clear
                echo "$panelname 已安装，应用操作"
                echo ""
                echo "------------------------"
                echo "1. 管理$panelname          2. 卸载$panelname"
                echo "------------------------"
                echo "0. 返回上一级选单"
                echo "------------------------"
                read -p "请输入你的选择: " sub_choice

                case $sub_choice in
                    1)
                        clear
                        $gongneng1
                        $gongneng1_1
                        ;;
                    2)
                        clear
                        $gongneng2
                        $gongneng2_1
                        $gongneng2_2
                        ;;
                    0)
                        break  # 跳出循环，退出菜单
                        ;;
                    *)
                        break  # 跳出循环，退出菜单
                        ;;
                esac
            else
                clear
                echo "安装提示"
                echo "如果您已经安装了其他面板工具或者LDNMP建站环境，建议先卸载，再安装$panelname！"
                echo "会根据系统自动安装，支持Debian，Ubuntu，Centos"
                echo "官网介绍: $panelurl "
                echo ""

                read -p "确定安装 $panelname 吗？(Y/N): " choice
                case "$choice" in
                    [Yy])
                        #iptables_open
                        install wget
                        if grep -q 'Alpine' /etc/issue; then
                            $ubuntu_mingling
                            $ubuntu_mingling2
                        elif grep -qi 'CentOS' /etc/redhat-release; then
                            $centos_mingling
                            $centos_mingling2
                        elif grep -qi 'Ubuntu' /etc/os-release; then
                            $ubuntu_mingling
                            $ubuntu_mingling2
                        elif grep -qi 'Debian' /etc/os-release; then
                            $ubuntu_mingling
                            $ubuntu_mingling2
                        else
                            echo "Unsupported OS"
                        fi
                                                    ;;
                    [Nn])
                        ;;
                    *)
                        ;;
                esac

            fi

}



current_timezone() {
    if grep -q 'Alpine' /etc/issue; then
       :
    else
       timedatectl show --property=Timezone --value
    fi

}


set_timedate() {
    shiqu="$1"
    if grep -q 'Alpine' /etc/issue; then
        install tzdata
        cp /usr/share/zoneinfo/${shiqu} /etc/localtime
        hwclock --systohc
    else
        timedatectl set-timezone ${shiqu}
    fi
}



linux_update() {

    # Update system on Debian-based systems
    if [ -f "/etc/debian_version" ]; then
        apt update -y && DEBIAN_FRONTEND=noninteractive apt full-upgrade -y
    fi

    # Update system on Red Hat-based systems
    if [ -f "/etc/redhat-release" ]; then
        yum -y update
    fi

    # Update system on Alpine Linux
    if [ -f "/etc/alpine-release" ]; then
        apk update && apk upgrade
    fi

}


linux_clean() {
    clean_debian() {
        apt autoremove --purge -y
        apt clean -y
        apt autoclean -y
        apt remove --purge $(dpkg -l | awk '/^rc/ {print $2}') -y
        journalctl --rotate
        journalctl --vacuum-time=1s
        journalctl --vacuum-size=50M
        apt remove --purge $(dpkg -l | awk '/^ii linux-(image|headers)-[^ ]+/{print $2}' | grep -v $(uname -r | sed 's/-.*//') | xargs) -y
    }

    clean_redhat() {
        yum autoremove -y
        yum clean all
        journalctl --rotate
        journalctl --vacuum-time=1s
        journalctl --vacuum-size=50M
        yum remove $(rpm -q kernel | grep -v $(uname -r)) -y
    }

    clean_alpine() {
        apk del --purge $(apk info --installed | awk '{print $1}' | grep -v $(apk info --available | awk '{print $1}'))
        apk autoremove
        apk cache clean
        rm -rf /var/log/*
        rm -rf /var/cache/apk/*

    }

    # Main script
    if [ -f "/etc/debian_version" ]; then
        # Debian-based systems
        clean_debian
    elif [ -f "/etc/redhat-release" ]; then
        # Red Hat-based systems
        clean_redhat
    elif [ -f "/etc/alpine-release" ]; then
        # Alpine Linux
        clean_alpine
    fi


}

new_ssh_port() {

  # 备份 SSH 配置文件
  cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

  sed -i 's/^\s*#\?\s*Port/Port/' /etc/ssh/sshd_config

  # 替换 SSH 配置文件中的端口号
  sed -i "s/Port [0-9]\+/Port $new_port/g" /etc/ssh/sshd_config
  rm -rf /etc/ssh/sshd_config.d/* /etc/ssh/ssh_config.d/*

  # 指定新端口放通
  open_firewall_port $new_port > /dev/null 2>&1

  # 重启 SSH 服务
  restart_ssh
  echo "SSH 端口已修改为: $new_port"

  sleep 1
  #iptables_open
  #remove iptables-persistent ufw firewalld iptables-services > /dev/null 2>&1

}

bbr_on() {

cat > /etc/sysctl.conf << EOF
net.core.default_qdisc=fq_pie
net.ipv4.tcp_congestion_control=bbr
EOF
sysctl -p

}

set_dns() {

cloudflare_ipv4="1.0.0.1"
google_ipv4="8.8.8.8"
cloudflare_ipv6="2606:4700:4700::1111"
google_ipv6="2001:4860:4860::8888"

# 禁用systemd-resolved.service
systemctl stop systemd-resolved.service
systemctl disable systemd-resolved.service
rm -f /etc/resolv.conf

# 检查机器是否有IPv6地址
ipv6_available=0
if [[ $(ip -6 addr | grep -c "inet6") -gt 0 ]]; then
    ipv6_available=1
fi

# 设置DNS地址为Cloudflare和Google（IPv4和IPv6）
echo "设置DNS为Cloudflare和Google"

# 设置IPv4地址
echo "nameserver $cloudflare_ipv4" > /etc/resolv.conf
echo "nameserver $google_ipv4" >> /etc/resolv.conf

# 如果有IPv6地址，则设置IPv6地址
if [[ $ipv6_available -eq 1 ]]; then
    echo "nameserver $cloudflare_ipv6" >> /etc/resolv.conf
    echo "nameserver $google_ipv6" >> /etc/resolv.conf
fi

echo "DNS地址已更新"
echo "------------------------"
cat /etc/resolv.conf
echo "------------------------"
}


restart_ssh() {

if command -v dnf &>/dev/null; then
    systemctl restart sshd
elif command -v yum &>/dev/null; then
    systemctl restart sshd
elif command -v apt &>/dev/null; then
    service ssh restart
elif command -v apk &>/dev/null; then
    service sshd restart
else
    echo "未知的包管理器!"
    return 1
fi

}


add_sshkey() {
#ssh-keygen -t rsa -b 4096 -C "xxxx@gmail.com" -f /root/.ssh/sshkey -N ""
read -p "请输入SSH公钥： " sshPublicKey

if [ -z "$sshPublicKey" ]; then
    sshPublicKey=$ssh_default_public_key
    echo -e "${red}您输入的公钥信息为空！这里展示一个示范公钥，请您注意删除 ${white}"
fi

mkdir -p ~/.ssh
echo ${sshPublicKey} >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

echo -e "您输入的公钥信息已经保存到 /.ssh/authorized_keys "
echo -e "您公钥信息为： "
echo "--------------------------------"
echo ${sshPublicKey}
echo "--------------------------------"

sed -i -e 's/^\s*#\?\s*PermitRootLogin .*/PermitRootLogin prohibit-password/' \
       -e 's/^\s*#\?\s*PasswordAuthentication .*/PasswordAuthentication no/' \
       -e 's/^\s*#\?\s*PubkeyAuthentication .*/PubkeyAuthentication yes/' \
       -e 's/^\s*#\?\s*ChallengeResponseAuthentication .*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
rm -rf /etc/ssh/sshd_config.d/* /etc/ssh/ssh_config.d/*
read -p "按任意键重启SSH以生效..." temp
restart_ssh
echo -e "${Green}ROOT私钥登录已开启，已关闭ROOT密码登录，重连将会生效${White}"

}


add_sshpasswd() {
echo "设置你的ROOT密码"
passwd
sed -i 's/^\s*#\?\s*PermitRootLogin.*/PermitRootLogin yes/g' /etc/ssh/sshd_config;
sed -i 's/^\s*#\?\s*PasswordAuthentication.*/PasswordAuthentication yes/g' /etc/ssh/sshd_config;
rm -rf /etc/ssh/sshd_config.d/* /etc/ssh/ssh_config.d/*
restart_ssh
echo -e "${Green}ROOT登录设置完毕！${White}"
server_reboot
}

root_use() {
clear
[ "$EUID" -ne 0 ] && echo -e "${Yellow}请注意，该功能需要root用户才能运行！${White}" && break_end && back_main
}

# 检查变量和初始化变量
chech_dependance() { 
    # 初始化变量
    Yellow='\033[33m'; White='\033[0m'; Green='\033[0;32m'; Blue='\033[0;34m'; Red='\033[31m'; Gray='\e[37m'; LightBlue='\033[96m'; DarkYellow='\033[93m'
    SYSCTLCONF=/etc/sysctl.conf
    GAICONF=/etc/gai.conf
    MARK="# CherryModified"

    # 检查CURL
    if [ ! -f /usr/bin/curl ]; then install curl; fi; 
    # 检查是否之前安装，如果没安装过的话，询问安装依赖
    if [ ! -f /usr/local/bin/ludo ]; then
        read -p "It's first run, Install dependencies？[Y/n] " yn
        # 如果是回车，也当作y
        [[ -z "${yn}" ]] && yn="y"
        if [[ ${yn} == [Yy] ]]; then
            install curl wget sudo net-tools ufw unzip
        fi
    fi

    # 初始化环境
    mkdir -p ${work_path}/work > /dev/null 2>&1
    mv -f ./ludo.sh ${work_path}/ludo.sh > /dev/null 2>&1
    cp -f ${work_path}/ludo.sh /usr/local/bin/ludo > /dev/null 2>&1
    cd ${work_path}/work
	startup_check_new_version="false"
    sh_new_ver=$(curl --connect-timeout 2 --max-time 2 -s "https://raw.githubusercontent.com/railzen/CherryScript/main/ludo.sh"|grep 'main_version="'|awk -F "=" '{print $NF}'|sed 's/\"//g'|head -1)
	

    if [ -n "$sh_new_ver" ]; then
        if [[ ${sh_new_ver} != ${main_version} ]]; then
            startup_check_new_version="true"
        fi
    fi
}


# ===========================================================================================
# =====================脚本从此处开始 =========================================================
# =====================卸载命令：rm -rf /opt/CherryScript/ /usr/local/bin/ludo================
# ===========================================================================================

if [[ ! $# = 0 && $1 = "dir" ]];then
    cd ${work_path}/work
    exit 0
elif [[ ! $# = 0 && $1 = "restart" ]];then
    # 快速重启所有本脚本创建的服务，用于更新配置
    ls /etc/systemd/system | grep Cherry- | xargs systemctl restart
    exit 0
elif [[ ! $# = 0 && $1 = "edit" ]];then
    # 快速重启所有本脚本创建的服务，用于更新配置
    vi $work_path/config/start.sh
    #ls /etc/systemd/system | grep Cherry- | xargs systemctl restart
    exit 0
fi

# 存在文件，检查依赖及展示菜单
chech_dependance
main_menu_start




