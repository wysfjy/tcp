#!/usr/bin/env python3
"""
KeepAlive类
"""

import os
import sys
import socket
from typing import Tuple, Optional

from utils import Logger, socket_set_opt, addr_to_uri


class KeepAlive(object):
    """KeepAlive类"""
    
    def __init__(self, host: str, port: int, source_host: str, source_port: int, 
                 interface: Optional[str] = None, udp: bool = False):
        self.sock = None
        self.host = host
        self.port = port
        self.source_host = source_host
        self.source_port = source_port
        self.interface = interface
        self.udp = udp
        self.reconn = False
    
    def __del__(self):
        if self.sock:
            self.sock.close()
    
    def _connect(self) -> None:
        """建立连接"""
        socket_type = socket.SOCK_DGRAM if self.udp else socket.SOCK_STREAM
        self.sock = socket.socket(socket.AF_INET, socket_type)
        
        try:
            socket_set_opt(
                self.sock,
                reuse       = True,
                bind_addr   = (self.source_host, self.source_port),
                interface   = self.interface,
                timeout     = 3
            )
            
            self.sock.connect((self.host, self.port))
            
            if not self.udp:
                Logger.debug("keep-alive: Connected to host %s" % (
                    addr_to_uri((self.host, self.port), udp=self.udp)
                ))
                if self.reconn:
                    Logger.info("keep-alive: connection restored")
                    
            self.reconn = False
            
        except Exception:
            self.sock.close()
            self.sock = None
            raise
    
    def keep_alive(self) -> None:
        """保持连接"""
        if self.sock is None:
            self._connect()
            
        if self.udp:
            self._keep_alive_udp()
        else:
            self._keep_alive_tcp()
            
        Logger.debug("keep-alive: OK")
    
    def disconnect(self) -> None:
        """断开连接"""
        if self.sock is not None:
            self.sock.close()
            self.sock = None
            self.reconn = True
    
    def _keep_alive_tcp(self) -> None:
        """TCP保持连接"""
        self.sock.sendall((
            "HEAD /natter-keep-alive HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: curl/8.0.0 (Natter)\r\n"
            "Accept: */*\r\n"
            "Connection: keep-alive\r\n"
            "\r\n" % self.host
        ).encode())
        
        buff = b""
        try:
            while True:
                buff = self.sock.recv(4096)
                if not buff:
                    raise OSError("Keep-alive server closed connection")
                    
        except socket.timeout as ex:
            if not buff:
                raise ex
            return
    
    def _keep_alive_udp(self) -> None:
        """UDP保持连接"""
        self.sock.send(
            struct.pack(
                "!HHHHHH", random.getrandbits(16), 0x0100, 0x0001, 0x0000, 0x0000, 0x0000
            ) + b"\x09keepalive\x06natter\x00" + struct.pack("!HH", 0x0001, 0x0001)
        )
        
        buff = b""
        try:
            while True:
                buff = self.sock.recv(1500)
                if not buff:
                    raise OSError("Keep-alive server closed connection")
                    
        except socket.timeout as ex:
            if not buff:
                raise ex
            return
