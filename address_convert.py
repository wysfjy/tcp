#!/usr/bin/env python3
"""
地址转换函数
"""

import os
import sys
import socket
import struct
from typing import Tuple, Optional

from utils import Logger


def ip2int(ip: str) -> int:
    """将IP地址转换为整数"""
    return struct.unpack("!L", socket.inet_aton(ip))[0]


def int2ip(n: int) -> str:
    """将整数转换为IP地址"""
    return socket.inet_ntoa(struct.pack("!L", n))


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
