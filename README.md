# docker-traefik-qbittorrent-wireguard-pia
Docker container which runs [qBittorrent](https://github.com/qbittorrent/qBittorrent)-nox (headless) client while connecting to PIA WireGuard using their official scripts. The whole thing hooks into traefik running on a HA stack.

# Specs and Features
* Docker Base: qbittorrentofficial/qbittorrent-nox:latest [qBittorrent](https://github.com/qbittorrent/qBittorrent) from the official Docker repo
* Uses the [PIA Wireguard manual-connection](https://github.com/pia-foss/manual-connections/) scripts.
* Adds [VueTorrent](https://github.com/VueTorrent/VueTorrent) (alternate web UI) which can be enabled (or not) by the user.
* IP tables killswitch to prevent IP leaking when VPN connection fails.
* Configurable UID and GID for config files and /downloads for qBittorrent.
* Automatically restarts the qBittorrent process in the event of it crashing.
* Works with PIA's port forward VPN servers to automatically enable forwarding in your container, and automatically sets the connection port in qBittorrent to match the forwarded port.

# Credits
* [tenseiken/docker-qbittorrent-wireguard](https://github.com/tenseiken/docker-qbittorrent-wireguard). 

I initally forked it but I was changing so much stuff out I decided to start from scratch. 

