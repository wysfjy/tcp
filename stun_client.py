#!/usr/bin/env python3
"""
STUN客户端类
"""

import os
import sys
import time
import random
import socket
import struct
from typing import List, Tuple, Optional

from utils import Logger, socket_set_opt, addr_to_uri


class StunClient(object):
    """STUN客户端类"""
    
    class ServerUnavailable(Exception):
        """STUN服务器不可用异常"""
        pass
    
    def __init__(self, stun_server_list: List[Tuple[str, int]], source_host: str = "0.0.0.0", 
                 source_port: int = 0, interface: Optional[str] = None, udp: bool = False):
        if not stun_server_list:
            raise ValueError("STUN server list is empty")
            
        self.stun_server_list = stun_server_list
        self.source_host = source_host
        self.source_port = source_port
        self.interface = interface
        self.udp = udp
    
    def get_mapping(self) -> Tuple[Tuple[str, int], Tuple[str, int]]:
        """获取地址映射"""
        first = self.stun_server_list[0]
        
        while True:
            try:
                return self._get_mapping()
            except StunClient.ServerUnavailable as ex:
                Logger.warning("stun: STUN server %s is unavailable: %s" % (
                    addr_to_uri(self.stun_server_list[0], udp = self.udp), ex
                ))
                self.stun_server_list.append(self.stun_server_list.pop(0))
                
                if self.stun_server_list[0] == first:
                    Logger.error("stun: No STUN server is available right now")
                    time.sleep(10)
    
    def _get_mapping(self) -> Tuple[Tuple[str, int], Tuple[str, int]]:
        """内部获取地址映射"""
        socket_type = socket.SOCK_DGRAM if self.udp else socket.SOCK_STREAM
        stun_host, stun_port = self.stun_server_list[0]
        
        sock = socket.socket(socket.AF_INET, socket_type)
        
        try:
            socket_set_opt(
                sock,
                reuse       = True,
                bind_addr   = (self.source_host, self.source_port),
                interface   = self.interface,
                timeout     = 3
            )
            
            sock.connect((stun_host, stun_port))
            inner_addr = sock.getsockname()
            self.source_host, self.source_port = inner_addr
            
            sock.send(struct.pack(
                "!LLLLL", 0x00010000, 0x2112a442, 0x4e415452,
                random.getrandbits(32), random.getrandbits(32)
            ))
            
            buff = sock.recv(1500)
            ip = port = 0
            payload = buff[20:]
            
            while payload:
                attr_type, attr_len = struct.unpack("!HH", payload[:4])
                if attr_type in [1, 32]:
                    _, _, port, ip = struct.unpack("!BBHL", payload[4:4+attr_len])
                    if attr_type == 32:
                        port ^= 0x2112
                        ip ^= 0x2112a442
                    break
                payload = payload[4 + attr_len:]
            else:
                raise ValueError("Invalid STUN response")
                
            outer_addr = socket.inet_ntop(socket.AF_INET, struct.pack("!L", ip)), port
            
            Logger.debug("stun: Got address %s from %s, source %s" % (
                addr_to_uri(outer_addr, udp=self.udp),
                addr_to_uri((stun_host, stun_port), udp=self.udp),
                addr_to_uri(inner_addr, udp=self.udp)
            ))
            
            return inner_addr, outer_addr
            
        except (OSError, ValueError, struct.error, socket.error) as ex:
            raise StunClient.ServerUnavailable(ex)
            
        finally:
            sock.close()
