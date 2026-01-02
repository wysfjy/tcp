#!/usr/bin/env python3
"""
主函数
"""

import os
import sys
import time
import json
import socket
import signal
import argparse
import subprocess
import requests
from typing import List, Tuple, Optional

from utils import Logger, socket_set_opt, addr_to_uri, addr_to_str
from exceptions import NatterExit, NatterExitException, NatterRetryException
from stun_client import StunClient
from keep_alive import KeepAlive
from port_test import PortTest
from forward import ForwardTestServer, ForwardSocket, ForwardNone
from docker_check import check_docker_network


__version__ = "2.2.1"


def run_natter_check() -> None:
    """运行natter检查"""
    # 这里可以添加检查逻辑
    pass


def natter_main(show_title: bool = True) -> None:
    """主函数"""
    argp = argparse.ArgumentParser(
        description="Expose your port behind full-cone NAT to the Internet.", add_help=False
    )
    
    group = argp.add_argument_group("options")
    group.add_argument(
        "--version", "-V", action="version", version="Natter %s" % __version__,
        help="show the version of Natter and exit"
    )
    group.add_argument(
        "--help", action="help", help="show this help message and exit"
    )
    group.add_argument(
        "--check", action="store_true", help="run natter-check and exit"
    )
    group.add_argument(
        "-v", action="store_true", help="verbose mode, printing debug messages"
    )
    group.add_argument(
        "-q", action="store_true", help="exit when mapped address is changed"
    )
    group.add_argument(
        "-u", action="store_true", help="UDP mode"
    )
    group.add_argument(
        "-U", action="store_true", help="enable UPnP/IGD discovery"
    )
    group.add_argument(
        "-k", type=int, metavar="<interval>", default=15,
        help="seconds between each keep-alive"
    )
    group.add_argument(
        "-s", metavar="<address>", action="append",
        help="hostname or address to STUN server"
    )
    group.add_argument(
        "-h", type=str, metavar="<address>", default=None,
        help="hostname or address to keep-alive server"
    )
    group.add_argument(
        "-e", type=str, metavar="<path>", default=None,
        help="script path for notifying mapped address"
    )
    
    group = argp.add_argument_group("bind options")
    group.add_argument(
        "-i", type=str, metavar="<interface>", default="0.0.0.0",
        help="network interface name or IP to bind"
    )
    group.add_argument(
        "-b", type=int, metavar="<port>", default=0,
        help="port number to bind"
    )
    
    group = argp.add_argument_group("forward options")
    group.add_argument(
        "-m", type=str, metavar="<method>", default=None,
        help="forward method, common values are 'iptables', 'nftables', "
             "'socat', 'gost' and 'socket'"
    )
    group.add_argument(
        "-t", type=str, metavar="<address>", default="0.0.0.0",
        help="IP address of forward target"
    )
    group.add_argument(
        "-p", type=int, metavar="<port>", default=0,
        help="port number of forward target"
    )
    group.add_argument(
        "-r", action="store_true", help="keep retrying until the port of forward target is open"
    )
    
    args = argp.parse_args()
    verbose = args.v
    udp_mode = args.u
    upnp_enabled = args.U
    interval = args.k
    stun_list = args.s
    keepalive_srv = args.h
    notify_sh = args.e
    bind_ip = args.i
    bind_interface = None
    bind_port = args.b
    method = args.m
    to_ip = args.t
    to_port = args.p
    keep_retry = args.r
    exit_when_changed = args.q
    
    if verbose:
        Logger.set_level(Logger.DEBUG)
    else:
        sys.tracebacklimit = 0
    
    if args.check:
        run_natter_check()
        sys.exit(0)
    
    # 验证参数
    if not isinstance(interval, int) or interval <= 0:
        raise ValueError("Interval must be a positive integer")
    
    if stun_list:
        for stun_srv in stun_list:
            # 验证STUN服务器地址
            pass
    
    if notify_sh:
        if not os.path.exists(notify_sh):
            raise ValueError(f"File not found: {notify_sh}")
    
    if not validate_ip(bind_ip, err=False):
        bind_interface = bind_ip
        bind_ip = "0.0.0.0"
    
    # 标准化IP地址
    bind_ip = socket.inet_ntoa(socket.inet_aton(bind_ip))
    to_ip = socket.inet_ntoa(socket.inet_aton(to_ip))
    
    # 默认STUN服务器列表
    if not stun_list:
        stun_list = [
            "fwa.lifesizecloud.com",
            "global.turn.twilio.com",
            "turn.cloudflare.com",
            "stun.nextcloud.com",
            "stun.freeswitch.org",
            "stun.voip.blackberry.com",
            "stun.sipnet.com",
            "stun.radiojar.com",
            "stun.sonetel.com",
            "stun.telnyx.com"
        ]
        if not udp_mode:
            stun_list = stun_list + [
                "turn.cloud-rtc.com:80"
            ]
        else:
            stun_list = [
                "stun.miwifi.com",
                "stun.chat.bilibili.com",
                "stun.hitv.com",
                "stun.cdnbye.com",
                "stun.douyucdn.cn:18000"
            ] + stun_list
    
    # 默认keepalive服务器
    if not keepalive_srv:
        keepalive_srv = "www.baidu.com"
        if udp_mode:
            keepalive_srv = "119.29.29.29"
    
    # 解析STUN服务器列表
    stun_srv_list: List[Tuple[str, int]] = []
    for item in stun_list:
        l = item.split(":", 2) + ["3478"]
        stun_srv_list.append((l[0], int(l[1])),)
    
    # 解析keepalive服务器
    if udp_mode:
        l = keepalive_srv.split(":", 2) + ["53"]
        keepalive_host, keepalive_port = l[0], int(l[1])
    else:
        l = keepalive_srv.split(":", 2) + ["80"]
        keepalive_host, keepalive_port = l[0], int(l[1])
    
    # 选择转发方法
    if not method:
        if to_ip == "0.0.0.0" and to_port == 0 and \
                bind_ip == "0.0.0.0" and bind_port == 0 and bind_interface is None:
            method = "test"
        elif to_ip == "0.0.0.0" and to_port == 0:
            method = "none"
        else:
            method = "socket"
    
    # 选择转发实现
    ForwardImpl = None
    if method == "none":
        ForwardImpl = ForwardNone
    elif method == "test":
        ForwardImpl = ForwardTestServer
    elif method == "socket":
        ForwardImpl = ForwardSocket
    else:
        raise ValueError(f"Unknown method name: {method}")
    
    # 显示标题
    if show_title:
        Logger.info("Natter v%s" % __version__)
        if len(sys.argv) == 1:
            Logger.info("Tips: Use `--help` to see help messages")
    
    # 检查Docker网络
    check_docker_network()
    
    # 初始化组件
    forwarder = ForwardImpl()
    port_test = PortTest()
    
    # STUN客户端
    stun = StunClient(stun_srv_list, bind_ip, bind_port, udp=udp_mode, interface=bind_interface)
    natter_addr, outer_addr = stun.get_mapping()
    bind_ip, bind_port = natter_addr
    
    # KeepAlive
    keep_alive = KeepAlive(keepalive_host, keepalive_port, bind_ip, bind_port, udp=udp_mode, interface=bind_interface)
    keep_alive.keep_alive()
    
    # 再次获取映射地址
    outer_addr_prev = outer_addr
    natter_addr, outer_addr = stun.get_mapping()
    if outer_addr != outer_addr_prev:
        Logger.warning("Network is unstable, or not full cone")
    
    # 设置目标IP
    if socket.inet_aton(to_ip) in [socket.inet_aton("127.0.0.1"), socket.inet_aton("0.0.0.0")]:
        to_ip = natter_addr[0]
    
    # 设置目标端口
    if not to_port:
        to_port = outer_addr[1]
    
    # 特殊处理
    if ForwardImpl in (ForwardNone, ForwardTestServer):
        to_ip, to_port = natter_addr
    
    # 启动转发
    to_addr = (to_ip, to_port)
    forwarder.start_forward(natter_addr[0], natter_addr[1], to_addr[0], to_addr[1], udp=udp_mode)
    NatterExit.set_atexit(forwarder.stop_forward)
    
    # UPnP
    upnp = None
    upnp_router = None
    upnp_ready = False
    
    if upnp_enabled:
        # 这里可以添加UPnP逻辑
        pass
    
    # 显示路由信息
    Logger.info()
    route_str = ""
    if ForwardImpl not in (ForwardNone, ForwardTestServer):
        route_str += "%s <--%s--> " % (addr_to_uri(to_addr, udp=udp_mode), method)
    route_str += "%s <--Natter--> %s" % (
        addr_to_uri(natter_addr, udp=udp_mode), addr_to_uri(outer_addr, udp=udp_mode)
    )
    Logger.info(route_str)
    
    # 上报信息
    requests.get(url=f"http://127.0.0.1:3319/shangbao/{addr_to_uri(outer_addr, udp=udp_mode, a=1)}/{to_addr[1]}/0")
    Logger.info()
    
    # 测试模式
    if ForwardImpl == ForwardTestServer:
        Logger.info("Test mode in on.")
        Logger.info("Please check [ %s://%s ]" % ("udp" if udp_mode else "http", addr_to_str(outer_addr)))
        Logger.info()
    
    # 调用通知脚本
    if notify_sh:
        protocol = "udp" if udp_mode else "tcp"
        inner_ip, inner_port = to_addr if method else natter_addr
        outer_ip, outer_port = outer_addr
        Logger.info("Calling script: %s" % notify_sh)
        subprocess.call([
            os.path.abspath(notify_sh), protocol, str(inner_ip), str(inner_port), str(outer_ip), str(outer_port)
        ], shell=False)
    
    # 测试端口
    if not udp_mode:
        ret1 = port_test.test_lan(to_addr, info=True)
        ret2 = port_test.test_lan(natter_addr, info=True)
        ret3 = port_test.test_lan(outer_addr, source_ip=natter_addr[0], interface=bind_interface, info=True)
        ret4 = port_test.test_wan(outer_addr, source_ip=natter_addr[0], interface=bind_interface, info=True)
        
        if ret1 == -1 and ret4 == 1:
            Logger.warning("!! Target port is closed !!")
            requests.get(url=f"http://127.0.0.1:3319/shangbao/{addr_to_uri(outer_addr, udp=udp_mode, a=1)}/{to_addr[1]}/{'当前内网端口未开，但已完成穿透，断线重连无法启用'}")
        elif ret1 == -1 and ret4 == -1:
            Logger.warning("!! Target port is closed !!")
            requests.get(url=f"http://127.0.0.1:3319/shangbao/{addr_to_uri(outer_addr, udp=udp_mode, a=1)}/{to_addr[1]}/{'当前内网端口未开，且未完成穿透'}")
        elif ret1 == 1 and ret3 == ret4 == -1:
            Logger.warning("!! Hole punching failed !!")
            requests.get(url=f"http://127.0.0.1:3319/shangbao/{addr_to_uri(outer_addr, udp=udp_mode, a=1)}/{to_addr[1]}/{'当前内网已开端口，但未完成穿透'}")
        elif ret3 == 1 and ret4 == -1:
            Logger.warning("!! You may be behind a firewall !!")
            requests.get(url=f"http://127.0.0.1:3319/shangbao/{addr_to_uri(outer_addr, udp=udp_mode, a=1)}/{to_addr[1]}/{'当前内网已成功，但未完成穿透'}")
        elif ret3 == -1 and ret4 == 1:
            Logger.warning("!! You may can't use auto retry when network is unstable !!")
            requests.get(url=f"http://127.0.0.1:3319/shangbao/{addr_to_uri(outer_addr, udp=udp_mode, a=1)}/{to_addr[1]}/{'当前内网未成功，但已完成穿透，断线重连将仅在外网ip未改变时成功（这不是你的问题，实际上，电信网络很容易遇到，我们对此无能为力）'}")
        
        Logger.info()
        
        # 重试
        if keep_retry and ret1 == -1:
            Logger.info("Retry after %d seconds..." % interval)
            time.sleep(interval)
            forwarder.stop_forward()
            keep_alive.disconnect()
            raise NatterRetryException("Target port is closed")
    
    # 主循环
    need_recheck = False
    cnt = 0
    while True:
        cnt = (cnt + 1) % 20
        if cnt == 0:
            need_recheck = True
        
        if need_recheck:
            Logger.debug("Start recheck")
            need_recheck = False
            
            # 检查LAN端口
            if udp_mode or port_test.test_lan(outer_addr, source_ip=natter_addr[0], interface=bind_interface) == -1:
                # 检查STUN
                _, outer_addr_curr = stun.get_mapping()
                if outer_addr_curr != outer_addr:
                    forwarder.stop_forward()
                    keep_alive.disconnect()
                    
                    if exit_when_changed:
                        Logger.info("Natter is exiting because mapped address has changed")
                        raise NatterExitException("Mapped address has changed")
                    
                    raise NatterRetryException("Mapped address has changed")
        
        # KeepAlive
        ts = time.time()
        try:
            keep_alive.keep_alive()
        except (OSError, socket.error) as ex:
            if hasattr(errno, "EADDRNOTAVAIL") and \
                    ex.errno == errno.EADDRNOTAVAIL:
                if exit_when_changed:
                    Logger.info("Natter is exiting because local IP address "
                                "has changed")
                    raise NatterExitException("Local IP address has changed")
                raise NatterRetryException("Local IP address has changed")
            
            if udp_mode:
                Logger.debug("keep-alive: UDP response not received: %s" % ex)
            else:
                Logger.error("keep-alive: connection broken: %s" % ex)
                
            keep_alive.disconnect()
            need_recheck = True
        
        # UPnP
        if upnp_ready:
            try:
                upnp.renew()
            except (OSError, socket.error) as ex:
                Logger.error("upnp: failed to renew upnp: %s" % ex)
        
        # 睡眠
        sleep_sec = interval - (time.time() - ts)
        if sleep_sec > 0:
            time.sleep(sleep_sec)


def main() -> None:
    """主入口"""
    signal.signal(signal.SIGTERM, lambda s,f: sys.exit(143))
    try:
        natter_main()
    except KeyboardInterrupt:
        sys.exit()


if __name__ == "__main__":
    main()
