#!/usr/bin/env python3
"""
工具函数和辅助类
"""

import os
import sys
import time
import socket
import threading
from typing import Tuple, Optional, Any


def socket_set_opt(sock: socket.socket, reuse: bool = False, bind_addr: Optional[Tuple[str, int]] = None, 
                   interface: Optional[str] = None, timeout: int = -1) -> socket.socket:
    """设置套接字选项"""
    if reuse:
        if hasattr(socket, "SO_REUSEADDR"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    
    if interface is not None:
        if hasattr(socket, "SO_BINDTODEVICE"):
            sock.setsockopt(
                socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b"\0"
            )
        else:
            raise RuntimeError("Binding to an interface is not supported on your platform.")
    
    if bind_addr is not None:
        sock.bind(bind_addr)
    
    if timeout != -1:
        sock.settimeout(timeout)
    
    return sock


def start_daemon_thread(target: callable, args: Tuple[Any, ...] = ()) -> threading.Thread:
    """启动守护线程"""
    th = threading.Thread(target=target, args=args)
    th.daemon = True
    th.start()
    return th


def addr_to_str(addr: Tuple[str, int]) -> str:
    """将地址转换为字符串格式"""
    return "%s:%d" % addr


def addr_to_uri(addr: Tuple[str, int], udp: bool = False, a: int = 0) -> str:
    """将地址转换为URI格式"""
    if a == 0:
        if udp:
            return "udp://%s:%d" % addr
        else:
            return "tcp://%s:%d" % addr
    else:
        return "%s:%d" % addr


def validate_ip(s: str, err: bool = True) -> bool:
    """验证IP地址格式"""
    try:
        socket.inet_aton(s)
        return True
    except (OSError, socket.error):
        if err:
            raise ValueError("Invalid IP address: %s" % s)
        return False


def validate_port(s: str, err: bool = True) -> bool:
    """验证端口号格式"""
    if str(s).isdigit() and int(s) in range(65536):
        return True
    if err:
        raise ValueError("Invalid port number: %s" % s)
    return False


def validate_addr_str(s: str, err: bool = True) -> bool:
    """验证地址字符串格式"""
    l = str(s).split(":", 1)
    if len(l) == 1:
        return True
    return validate_port(l[1], err)


def validate_positive(s: str, err: bool = True) -> bool:
    """验证正整数格式"""
    if str(s).isdigit() and int(s) > 0:
        return True
    if err:
        raise ValueError("Not a positive integer: %s" % s)
    return False


def validate_filepath(s: str) -> bool:
    """验证文件路径是否存在"""
    if not os.path.exists(s):
        raise ValueError("File not found: %s" % s)
    return True


def ip_normalize(ipaddr: str) -> str:
    """标准化IP地址格式"""
    return socket.inet_ntoa(socket.inet_aton(ipaddr))


def set_reuse_port(port: int) -> None:
    """设置端口重用（空实现）"""
    pass


class Logger(object):
    """日志工具类"""
    
    DEBUG = 0
    INFO  = 1
    WARN  = 2
    ERROR = 3
    rep = {DEBUG: "D", INFO: "I", WARN: "W", ERROR: "E"}
    level = INFO
    
    @staticmethod
    def set_level(level: int) -> None:
        Logger.level = level
    
    @staticmethod
    def get_timestr() -> str:
        return "%04d-%02d-%02d %02d:%02d:%02d" % time.localtime()[:6]
    
    @staticmethod
    def debug(text: str = "") -> None:
        if Logger.level <= Logger.DEBUG:
            sys.stderr.write(("%s [%s] %s\n") % (
                Logger.get_timestr(), Logger.rep[Logger.DEBUG], text
            ))
    
    @staticmethod
    def info(text: str = "") -> None:
        if Logger.level <= Logger.INFO:
            sys.stderr.write(("%s [%s] %s\n") % (
                Logger.get_timestr(), Logger.rep[Logger.INFO], text
            ))
    
    @staticmethod
    def warning(text: str = "") -> None:
        if Logger.level <= Logger.WARN:
            sys.stderr.write(("%s [%s] %s\n") % (
                Logger.get_timestr(), Logger.rep[Logger.WARN], text
            ))
    
    @staticmethod
    def error(text: str = "") -> None:
        if Logger.level <= Logger.ERROR:
            sys.stderr.write(("%s [%s] %s\n") % (
                Logger.get_timestr(), Logger.rep[Logger.ERROR], text
            ))
