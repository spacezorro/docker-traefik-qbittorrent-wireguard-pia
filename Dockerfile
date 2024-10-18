FROM qbittorrentofficial/qbittorrent-nox:latest

RUN mkdir -p /downloads /config/qBittorrent/config /etc/qbittorrent /etc/vuetorrent /etc/wireguard /opt/piavpn-manual /pia-scripts

RUN apk add --no-cache \
    jq \
    kmod \
    bash \
    curl \
    ulogd \
    procps \
    shadow \
    ncurses \
    coreutils \
    moreutils \
    net-tools \
    bind-tools \
    libnatpmp \
    ipset \
    ipcalc \
    iptables \
    iputils-ping \
    iptables-legacy \
    ca-certificates \
    wireguard-tools \
    openresolv \
    openssl 

# Install VueTorrent (Enabled later)
RUN apk --no-cache add unzip \
    && VUETORRENT_RELEASE=$(curl -sX GET "https://api.github.com/repos/VueTorrent/VueTorrent/tags" | jq '.[] | .name' | head -n 1 | tr -d '"') \
    && curl -o vuetorrent.zip -L "https://github.com/VueTorrent/VueTorrent/releases/download/${VUETORRENT_RELEASE}/vuetorrent.zip" \
    && unzip vuetorrent.zip -d /etc \
    && rm vuetorrent.zip \
    && apk del unzip 

# The default config file for qbittorrent to use. The PIA script will edit the port.
COPY ./config/qBittorrent.conf /config/qBittorrent/config/qBittorrent.conf
COPY ./config/categories.json /config/qBittorrent/config/categories.json

# Jump through flaming hoops to get iptables logs
COPY ./config/ulog.conf /etc/ulogd.conf

# We are not running privileged. Modify wg-quick so it doesn't die without --privileged
# To avoid confusion, also suppress the error message that displays even when pre-set to 1 on container creation
RUN sed -i 's/cmd sysctl.*/set +e \&\& sysctl -q net.ipv4.conf.all.src_valid_mark=1 \&> \/dev\/null \&\& set -e/' /usr/bin/wg-quick

# Copy just the WG scripts 
COPY ./pia-scripts/ /pia-scripts
RUN rm -rf /pia-scripts/openvpn_config
RUN rm -f /pia-scripts/connect_to_openvpn_with_token.sh

# Make the PIA official script non-interactive
RUN awk ' \
    /^[[:space:]]*read/ { \
        n = split($0, words); \
        lword = words[n]; \
        if (lword == "DISABLE_IPV6") { \
            print lword "=y"; \
        } else if (lword == "serverSelection") { \
            print lword "=1"; \
        } else if (lword == "latencyInput") { \
            print lword "=0"; \
        } else if (lword == "connection_method") { \
            print lword "=W"; \
        } else if (lword == "setDNS") { \
            print lword "=Y"; \
        } else { \
            print lword "=n"; \
        } \
        next; \
    } \
    { print $0 } ' /pia-scripts/run_setup.sh > /tmp/temp.txt 
RUN mv /tmp/temp.txt /pia-scripts/run_setup.sh

# Make PIA script put the port where we can get it later
RUN sed -i -r 's|    # sleep 15 minutes|    echo "Setting Port to $port" ; echo $port >/tmp/wg-port.txt|' /pia-scripts/port_forwarding.sh

RUN chmod +x /pia-scripts/*.sh

# Healthcheck
COPY ./healthcheck.sh /
RUN chmod +x /healthcheck.sh

COPY ./start.sh /
RUN chmod +x /start.sh

VOLUME /config /downloads

ENTRYPOINT ["/bin/bash", "/start.sh"]
