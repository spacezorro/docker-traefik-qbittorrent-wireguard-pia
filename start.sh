#!/bin/bash
#

set -e
declare -A PIDS

net_admin_bit=0x4000000
cap_eff="0x$(grep CapEff /proc/self/status | awk '{print $2}')"
if [[ $((cap_eff & net_admin_bit)) -ne 0 ]]
then
  echo "[ERROR] cap_net_admin is not set" | ts '%Y-%m-%d %H:%M:%.S'
  echo "[ERROR]   in docker compose use  cap_add: NET_ADMIN" | ts '%Y-%m-%d %H:%M:%.S'
  echo "[ERROR]   in docker run use  --cap-add NET_ADMIN" | ts '%Y-%m-%d %H:%M:%.S'
  sleep 30
  exit 1
else
  echo "[INFO] cap_net_admin is set" | ts '%Y-%m-%d %H:%M:%.S'
fi

echo "[INFO] Checking sysctl parameters..." | ts '%Y-%m-%d %H:%M:%.S'
declare -A params=(
  ["net.ipv6.conf.default.disable_ipv6"]="1"
  ["net.ipv6.conf.all.disable_ipv6"]="1"
  ["net.ipv4.conf.all.rp_filter"]="2"
  ["net.ipv4.conf.all.src_valid_mark"]="1"
)
for param in "${!params[@]}"
do
  value=$(sysctl -n "$param")
  expected="${params[$param]}"
  if [[ "$value" == "$expected" ]]
  then
    echo "[DEBUG] $param is set correctly to $value" | ts '%Y-%m-%d %H:%M:%.S'
  else
    echo "[ERROR] $param is set to $value (expected $expected)" | ts '%Y-%m-%d %H:%M:%.S'
    echo "[ERROR]   in docker compose use  sysctls: $param=$expected" | ts '%Y-%m-%d %H:%M:%.S'
    echo "[ERROR]   in docker run use  --sysctl $param=$expected" | ts '%Y-%m-%d %H:%M:%.S'
    sleep 30
    exit 1
  fi
done

if [[ -z "${PUID}" ]]
then
  echo "[INFO] PUID not defined. Defaulting to 1001" | ts '%Y-%m-%d %H:%M:%.S'
  export PUID="1001"
  qbtUID=$(id -u qbtUser)
  if [[ ${PUID} != $qbtUID ]]
  then
    echo "[INFO] Changing qbtUser to match PUID" | ts '%Y-%m-%d %H:%M:%.S'
    usermod -u ${PUID} qbtUser
  fi
fi

if [[ -z "${PGID}" ]]
then
  echo "[INFO] PGID not defined. Defaulting to 1001" | ts '%Y-%m-%d %H:%M:%.S'
  export PGID="1001"
  qbtGID=$(id -g qbtUser)
  if [[  ${PGID} != $qbtGID ]]
  then
    echo "[INFO] Changing qbtUser to match PGID" | ts '%Y-%m-%d %H:%M:%.S'
    groupmod -g ${PGID} qbtUser
  fi
fi
# Get some network stuff before we let PIA/Wireguard step on it
docker_interface=$(netstat -ie | grep -vE "lo|tun|tap|wg|pia" | sed -n '1!p' | head -n 1 | cut -d : -f 1)
docker_ip=$(ifconfig "${docker_interface}" | grep -o "inet [0-9]*\.[0-9]*\.[0-9]*\.[0-9]*" | grep -o "[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*")
docker_network=$(ip addr show $docker_interface | awk '/inet / {split($2, a, "."); a[4]=0; print a[1]"."a[2]"."a[3]"."a[4]""substr($2, index($2,"/"))}')

LAN_IP=$(traceroute -n -i $docker_interface -m 2 1.1.1.1 | awk 'NR==3 {print $2}')
LAN_NETWORK=$(echo $LAN_IP | awk -F. '{print $1"."$2"."$3".0/24"}')
echo "[INFO] Docker Host ip $LAN_IP network is $LAN_NETWORK" | ts '%Y-%m-%d %H:%M:%.S'
DEFAULT_GATEWAY=$(ip -4 route list 0/0 | cut -d ' ' -f 3)
echo "[INFO] Default gateway defined as ${DEFAULT_GATEWAY}" | ts '%Y-%m-%d %H:%M:%.S'

echo "[INFO] route defined as follows..." | ts '%Y-%m-%d %H:%M:%.S'
echo "--------------------" | ts '%Y-%m-%d %H:%M:%.S'
ip route show 2>&1 | ts '%Y-%m-%d %H:%M:%.S'
echo "--------------------" | ts '%Y-%m-%d %H:%M:%.S'

echo "[INFO] Starting Wireguard..."  | ts '%Y-%m-%d %H:%M:%.S'
export PREFERRED_REGION=${PREFERRED_REGION:=ca}
export AUTOCONNECT=${AUTOCONNECT:=true}
export PIA_USER=${PIA_USER:=p0123456}
export PIA_PASS=${PIA_PASS:=xxxxxxxx}
export DIP_TOKEN=${DIP_TOKEN:=no}
export VPN_PROTOCOL=wireguard
export DISABLE_IPV6=yes
export MAX_LATENCY=0.1
export PIA_DNS=true
export PIA_PF=true
( 
  # Run PIA up to 3 times. Pass failing up so the container dies
  for i in {1..3}
  do
    cd /pia-scripts
    bash run_setup.sh 2>&1 | sed 's/^/[PIA-WG] /' | ts '%Y-%m-%d %H:%M:%.S' 
    # Because PIA_PF=true the script should exit because it is looping refreshing the forwarding port
    echo "[ERROR][PIA-WG] PIA Wireguard Exited!! It shouldn't do that. Restarting $i/3..."  | ts '%Y-%m-%d %H:%M:%.S'
  done
  echo "[ERROR][PIA-WG] PIA Wireguard Exited too many times!! Check the PIA account."  | ts '%Y-%m-%d %H:%M:%.S'
  exit 1
) &
PIDS["PIA"]=$!

# What if wireguard never comes up
max_loops=60
for ((loop=0; loop<max_loops; loop++)); do
    set +e ; tunnelstat=$(netstat -ie | grep "pia") ; set -e
    [[ -n "${tunnelstat}" ]] && break
    echo "[INFO] Waiting for Wireguard Interface $((loop + 1))/$max_loops attempts..." | ts '%Y-%m-%d %H:%M:%.S'
    sleep 10
    if [[ $loop -ge $((max_loops - 1)) ]]; then
        echo "[ERROR] Wireguard Interface not found after $max_loops attempts. Exiting." | ts '%Y-%m-%d %H:%M:%.S'
        exit 1
    fi
done

# Fix the route for the WebUi
echo "[INFO] Adding ${LAN_NETWORK} as route via docker eth0" | ts '%Y-%m-%d %H:%M:%.S'
ip route add "${LAN_NETWORK}" via "${DEFAULT_GATEWAY}" dev eth0
echo "[INFO] route defined as follows..." | ts '%Y-%m-%d %H:%M:%.S'
echo "--------------------" | ts '%Y-%m-%d %H:%M:%.S'
ip route show 2>&1 | ts '%Y-%m-%d %H:%M:%.S'
echo "--------------------" | ts '%Y-%m-%d %H:%M:%.S'

# Firewall
iptables_version=$(iptables -V)
echo "[INFO] The container is currently running ${iptables_version}." | ts '%Y-%m-%d %H:%M:%.S'

echo "[INFO] Populating ipset hashtable for HTTPS PIA servers" | ts '%Y-%m-%d %H:%M:%.S'
ipset create piawebservers hash:ip
for ip in $(dig +short serverlist.piaservers.net)
do
  ipset add piawebservers $ip
  #echo "[DEBUG] Adding $ip to WEB ipset"  | ts '%Y-%m-%d %H:%M:%.S'
done
echo "IP's added to WEB ipset $(ipset list piawebservers | grep -c '^')" | ts '%Y-%m-%d %H:%M:%.S'

echo "[INFO] Populating ipset hashtable for VPN PIA servers" | ts '%Y-%m-%d %H:%M:%.S'
ipset create piavpnservers hash:ip
for ip in $(curl -s https://serverlist.piaservers.net/vpninfo/servers/v6|head -n1|jq -r '.regions[]|select(.port_forward==true)|.servers.wg[].ip')
do
  ipset add piavpnservers $ip
  #echo "[DEBUG] Adding $ip to VPN ipset"  | ts '%Y-%m-%d %H:%M:%.S'
done
echo "IP's added to VPN ipset $(ipset list piavpnservers | grep -c '^')" | ts '%Y-%m-%d %H:%M:%.S'

iptables -N PIA_RULE_I
iptables -N PIA_RULE_O
iptables -P INPUT DROP
ip6tables -P INPUT DROP 1>&- 2>&-
iptables -A INPUT -j PIA_RULE_I
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i pia -j ACCEPT
iptables -A INPUT -i "${docker_interface}" -p udp --sport 53 -j ACCEPT
iptables -A INPUT -i "${docker_interface}" -p tcp --sport 53 -j ACCEPT
iptables -A INPUT -i "${docker_interface}" -p tcp --dport 8080 -j ACCEPT
iptables -A INPUT -i "${docker_interface}" -p tcp --sport 8080 -j ACCEPT
iptables -A INPUT -i "${docker_interface}" -m set --match-set piawebservers src -p tcp --dport 443 -j ACCEPT
#iptables -A INPUT -i "${docker_interface}" -m set --match-set piavpnservers src -p udp -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -j NFLOG --nflog-prefix "[IPTables-Dropped][IN ] "
iptables -P OUTPUT DROP
ip6tables -P OUTPUT DROP 1>&- 2>&-
iptables -A OUTPUT -j PIA_RULE_O
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -o pia -j ACCEPT
iptables -A OUTPUT -o "${docker_interface}" -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -o "${docker_interface}" -p tcp --dport 53 -j ACCEPT
iptables -A OUTPUT -o "${docker_interface}" -p tcp --dport 8080 -j ACCEPT
iptables -A OUTPUT -o "${docker_interface}" -p tcp --sport 8080 -j ACCEPT
iptables -A OUTPUT -o "${docker_interface}" -m set --match-set piawebservers dst -p tcp --dport 443 -j ACCEPT
#iptables -A OUTPUT -o "${docker_interface}" -m set --match-set piavpnservers dst -p udp -j ACCEPT
iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT ! -o pia -m mark ! --mark $(wg show pia fwmark) -m addrtype ! --dst-type LOCAL -j NFLOG --nflog-prefix "[IPTables-KILLSWITCH][PIA] "
iptables -A OUTPUT ! -o pia -m mark ! --mark $(wg show pia fwmark) -m addrtype ! --dst-type LOCAL -j REJECT
iptables -A OUTPUT -j NFLOG --nflog-prefix "[IPTables-Dropped][OUT] "

pia_endpoint=$(grep -E '^Endpoint' /etc/wireguard/pia.conf | awk -F ' = ' '{print $2}')
pia_endpoint_ip=$(echo $pia_endpoint | cut -d':' -f1)
pia_endpoint_port=$(echo $pia_endpoint | cut -d':' -f2)
iptables -A PIA_RULE_I -p udp -d $pia_endpoint_ip --sport $pia_endpoint_port -j ACCEPT
iptables -A PIA_RULE_O -p udp -s $pia_endpoint_ip --dport $pia_endpoint_port -j ACCEPT

echo "[INFO] iptables defined as follows..." | ts '%Y-%m-%d %H:%M:%.S'
echo "--------------------" | ts '%Y-%m-%d %H:%M:%.S'
iptables -S 2>&1 | ts '%Y-%m-%d %H:%M:%.S'
echo "--------------------" | ts '%Y-%m-%d %H:%M:%.S'

#echo "[INFO] Starting iptables logger in stderr..." | ts '%Y-%m-%d %H:%M:%.S'
#( 
#  # This starts ulog and eats the logfile and spits it to stderr a line at a time
#  ulogd -d
#  while true
#  do
#    if [[ ! -s /var/log/nflog ]]
#    then
#        sleep 5
#        continue
#    fi
#    # nflog has it's own timestamp so we don't need ts
#    head -n 1 /var/log/nflog >&2
#    sed -i '1d' /var/log/nflog
#    sleep 1
#  done
#) &

# Make the logging of the iptables go to STDERR
ulogd -d
PIDS["ULOG"]=$!
ln -sf /proc/1/fd/2 /var/log/nflog

# Set up things
mkdir -p /config/qBittorrent/config
chown -R ${PUID}:${PGID} /config/qBittorrent
if [ ! -e /config/qBittorrent/config/qBittorrent.conf ]
then
  echo "[WARNING] qBittorrent.conf is missing, this is normal for the first launch! Copying template." | ts '%Y-%m-%d %H:%M:%.S'
  cp /etc/qbittorrent/qBittorrent.conf /config/qBittorrent/config/qBittorrent.conf
  chmod 755 /config/qBittorrent/config/qBittorrent.conf
  chown ${PUID}:${PGID} /config/qBittorrent/config/qBittorrent.conf
fi

echo "[INFO] Updating the WebUi internal listening IP ($docker_ip)" | ts '%Y-%m-%d %H:%M:%.S'
sed -i "s|^WebUI.Address=.*|WebUI\\\Address=$docker_ip|" /config/qBittorrent/config/qBittorrent.conf

if [[ -f /tmp/wg-port.txt ]]
then
  setPort=$(cat /tmp/wg-port.txt)
  echo "[INFO] Updating the Torrent Port ($setPort)" | ts '%Y-%m-%d %H:%M:%.S'
  sed -i "s|^Session.Port=.*|Session\\\Port=$setPort|" /config/qBittorrent/config/qBittorrent.conf
fi

echo "[INFO] Whitelisting logins for docker (${docker_network}) and host (${LAN_NETWORK}) networks" | ts '%Y-%m-%d %H:%M:%.S'
sed -i "s|^WebUI.AuthSubnetWhitelist=.*|WebUI\\\AuthSubnetWhitelist=${docker_network}, ${LAN_NETWORK}|" /config/qBittorrent/config/qBittorrent.conf

echo "[INFO] Starting qBittorrent logger in stderr..." | ts '%Y-%m-%d %H:%M:%.S'
mkdir -p /tmp/qbittorrent.log
ln -sf /proc/1/fd/2 /tmp/qbittorrent.log

# Start qBittorrent
echo "[INFO] Starting qBittorrent daemon..." | ts '%Y-%m-%d %H:%M:%.S'
chmod -R 755 /config/qBittorrent
bash /entrypoint.sh &>/dev/null &
PIDS["QBT"]=$!
        
#( 
#  # This moves the logfile and cats it to stderr
#  log=/config/qBittorrent/data/logs/qbittorrent.log
#  while true
#  do
#    if [[ ! -s $log ]]
#    then
#        sleep 5
#        continue
#    fi
#    mv ${log} ${log}.logger
#    cat ${log}.logger >&2
#    rm ${log}.logger
#  done
#) &
#PIDS["QLOG"]=$!

# wait for the entrypoint.sh script to finish and grab the qbittorrent pid
while ! pgrep -f "qbittorrent-nox" >/dev/null
do
  sleep 0.5
done

is_wg_down=0
is_wg_down_die=5
qbittorrentpid=$(pgrep -f "qbittorrent-nox")
echo "[INFO] qBittorrent daemon started (pid $qbittorrentpid)" | ts '%Y-%m-%d %H:%M:%.S'
while true
do

  if ! ps -p $qbittorrentpid &>/dev/null
  then
    echo "[ERROR] qBittorrent daemon is not running. Restarting..." | ts '%Y-%m-%d %H:%M:%.S'
    bash /entrypoint.sh &>/dev/null & 
    PIDS["QBT"]=$!
            
    # wait for the entrypoint.sh script to finish and grab the qbittorrent pid
    while ! pgrep -f "qbittorrent-nox" &>/dev/null
    do
      sleep 0.5
    done
    qbittorrentpid=$(pgrep -f "qbittorrent-nox")
  fi

  # for the "healthcheck"
  echo "declare -A PIDS" > /tmp/healthcheck.inc
  for p in "${!PIDS[@]}"
  do
    echo "PIDS[$p]=${PIDS[$p]}" >> /tmp/healthcheck.inc
  done

  pia_endpoint=$(grep -E '^Endpoint' /etc/wireguard/pia.conf | awk -F ' = ' '{print $2}')
  pia_endpoint_ip=$(echo $pia_endpoint | cut -d':' -f1)
  pia_endpoint_port=$(echo $pia_endpoint | cut -d':' -f2)
  if ! iptables -L PIA_RULE_I | grep -q "$IP.*$PORT"
  then
    echo "[ERROR] Replacing PIA Wireguard Endpoint (new $pia_endpoint)" | ts '%Y-%m-%d %H:%M:%.S'
    iptables -I PIA_RULE_I -p udp -d $pia_endpoint_ip --sport $pia_endpoint_port -j ACCEPT
    for i in $(seq 2 $(iptables -L INPUT --line-numbers | wc -l))
    do
     iptables -D PIA_RULE_I $i
    done
  fi

  if ! iptables -L PIA_RULE_O | grep -q "$IP.*$PORT"
  then
    echo "[ERROR] Replacing PIA Wireguard Endpoint (new $pia_endpoint)" | ts '%Y-%m-%d %H:%M:%.S'
    iptables -I PIA_RULE_O -p udp -s $pia_endpoint_ip --dport $pia_endpoint_port -j ACCEPT
    for i in $(seq 2 $(iptables -L INPUT --line-numbers | wc -l))
    do
     iptables -D PIA_RULE_O $i
    done
  fi
  
  if ! ping -I "${docker_interface}" -c 10 1.1.1.1 &>/dev/null
  then
    echo "[ERROR] External Network is possibly down." | ts '%Y-%m-%d %H:%M:%.S'
    #echo "[INFO] Restarting container." | ts '%Y-%m-%d %H:%M:%.S'
    #exit 1
  fi

  pia_ip=$(grep -E '^Address' /etc/wireguard/pia.conf | awk -F ' = ' '{print $2}')
  pia_dns=$(grep -E '^DNS' /etc/wireguard/pia.conf | awk -F ' = ' '{print $2}')

  if ! ping -n -I pia -c 10 1.1.1.1 &>/dev/null 
  then
    is_wg_down=$((is_wg_down + 1))
    echo "[ERROR] Wireguard Network is down $is_wg_down times. (die at $is_wg_down_die)" | ts '%Y-%m-%d %H:%M:%.S'
    echo "[ERROR] Wireguard status" | ts '%Y-%m-%d %H:%M:%.S'
    echo "--------------------" | ts '%Y-%m-%d %H:%M:%.S'
    wg | grep -v "=" | ts '%Y-%m-%d %H:%M:%.S'
    echo "--------------------" | ts '%Y-%m-%d %H:%M:%.S'
    if [[ $is_wg_down -ge $is_wg_down_die ]]
    then
      echo "[INFO] Restarting container." | ts '%Y-%m-%d %H:%M:%.S'
      exit 1
    fi
  else
    [[ $is_wg_down -gt 0 ]] && echo "[INFO] Wireguard Network is back up after $is_wg_down failed attempts." | ts '%Y-%m-%d %H:%M:%.S'
    is_wg_down=0
  fi
          
  for ip in $(dig @$pia_dns -b $pia_ip +short serverlist.piaservers.net)
  do
    if ! ipset test piawebservers $ip &>/dev/null
    then
      ipset add piawebservers $ip &>/dev/null || true
      #echo "[DEBUG] Adding $ip to WEB ipset"  | ts '%Y-%m-%d %H:%M:%.S'
    fi
  done

  for ip in $(curl -s https://serverlist.piaservers.net/vpninfo/servers/v6|head -n1|jq -r '.regions[]|select(.port_forward==true)|.servers.wg[].ip')
  do
    if ! ipset test piavpnservers $ip &>/dev/null
    then
      ipset add piavpnservers $ip &>/dev/null || true
      #echo "[DEBUG] Adding $ip to VPN ipset"  | ts '%Y-%m-%d %H:%M:%.S'
    fi
  done

  WEBUI_URL="http://${docker_ip}:8080"
  loginData="username=${WEBUI_USER:=admin}&password=${WEBUI_PASS:=adminadmin}"
  cookie=$(curl -i --silent --interface $docker_interface --header "Referer: $WEBUI_URL" --data $loginData $WEBUI_URL/api/v2/auth/login | grep "set-cookie" | awk '/set-cookie:/ {print $2}' | sed 's/;//') >/dev/null 2>&1
  if [[ $cookie ]]
  then
    setPort=$(curl --silent --interface $docker_interface $WEBUI_URL/api/v2/app/preferences --cookie $cookie | jq '.listen_port') >/dev/null 2>&1
    if [[ -f /tmp/wg-port.txt ]]
    then
      currentPort=$(cat /tmp/wg-port.txt)
    else
      echo "[WARNING] Unable to get the forwarded port" | ts '%Y-%m-%d %H:%M:%.S'
      currentPort=0
    fi
    if [[ $setPort -ne $currentPort ]]
    then
      echo "[INFO] Changing the port from $setPort to $currentPort" | ts '%Y-%m-%d %H:%M:%.S'
      portData="json={\"listen_port\":$currentPort}"
      curl -i --silent --interface $docker_interface --data $portData $WEBUI_URL/api/v2/app/setPreferences --cookie $cookie >/dev/null 2>&1
    fi
    curl --silent -X 'POST' "$WEBUI_URL/api/v2/auth/logout" -H 'accept: */*' -d '' --cookie $cookie >/dev/null 2>&1
  else
    echo "[WARNING] Unable to log into the web UI." | ts '%Y-%m-%d %H:%M:%.S'
  fi
  unset cookie

  sleep 30
done
        
echo "[ERROR] You should never reach here" | ts '%Y-%m-%d %H:%M:%.S'
exit 1
        
