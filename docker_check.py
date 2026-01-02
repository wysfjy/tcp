#!/usr/bin/env python3
"""
Docker网络检查
"""

import os
import socket

from utils import Logger


def check_docker_network() -> None:
    """检查Docker网络配置"""
    if not sys.platform.startswith("linux"):
        return
        
    if not os.path.exists("/.dockerenv"):
        return
        
    if not os.path.isfile("/sys/class/net/eth0/address"):
        return
        
    fo = open("/sys/class/net/eth0/address", "r")
    macaddr = fo.read().strip()
    fo.close()
    
    hostname = socket.gethostname()
    try:
        ipaddr = socket.gethostbyname(hostname)
    except socket.gaierror:
        Logger.warning("check-docket-network: Cannot resolve hostname `%s`" % hostname)
        return
        
    docker_macaddr = "02:42:" + ":".join(["%02x" % int(x) for x in ipaddr.split(".")])
    if macaddr == docker_macaddr:
        raise RuntimeError("Docker's `--net=host` option is required.")
        
    if not os.path.isfile("/proc/sys/kernel/osrelease"):
        return
        
    fo = open("/proc/sys/kernel/osrelease", "r")
    uname_r = fo.read().strip()
    fo.close()
    
    uname_r_sfx = uname_r.rsplit("-").pop()
    if uname_r_sfx.lower() in ["linuxkit", "wsl2"] and hostname.lower() == "docker-desktop":
        raise RuntimeError("Network from Docker Desktop is not supported.")
