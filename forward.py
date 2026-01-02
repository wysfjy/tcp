#!/usr/bin/env python3
"""
转发相关类
"""

import os
import sys
import time
import socket
import threading
from typing import Tuple, Optional

from utils import Logger, socket_set_opt, addr_to_uri, start_daemon_thread


class ForwardTestServer(object):
    """测试转发服务器类"""
    
    def __init__(self):
        self.sock = None
        self.buff_size = 8192
        self.timeout = 3
    
    def __del__(self):
        self.stop_forward()
    
    def start_forward(self, ip: str, port: int, toip: str, toport: int, udp: bool = False) -> None:
        """启动转发"""
        sock_type = socket.SOCK_DGRAM if udp else socket.SOCK_STREAM
        self.sock = socket.socket(socket.AF_INET, sock_type)
        
        try:
            socket_set_opt(
                self.sock,
                reuse       = True,
                bind_addr   = ("", port)
            )
            
            Logger.debug("fwd-test: Starting test server at %s" %
                         addr_to_uri((ip, port), udp=udp))
            
            if udp:
                th = start_daemon_thread(self._test_server_run_udp)
            else:
                th = start_daemon_thread(self._test_server_run_http)
                
            time.sleep(1)
            if not th.is_alive():
                raise OSError("Test server thread exited too quickly")
                
        except Exception:
            self.sock.close()
            self.sock = None
            raise
    
    def _test_server_run_http(self) -> None:
        """HTTP测试服务器运行"""
        self.sock.listen(5)
        while self.sock and self.sock.fileno() != -1:
            try:
                conn, addr = self.sock.accept()
                Logger.debug("fwd-test: got client %s" % (addr,))
                
            except (OSError, socket.error):
                return
                
            try:
                conn.settimeout(self.timeout)
                conn.recv(self.buff_size)
                
                content = "<html><body><h1>It works!</h1><hr/>Natter</body></html>"
                content_len = len(content.encode())
                
                data = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/html\r\n"
                    "Content-Length: %d\r\n"
                    "Connection: close\r\n"
                    "Server: Natter\r\n"
                    "\r\n"
                    "%s\r\n" % (content_len, content)
                ).encode()
                
                conn.sendall(data)
                conn.shutdown(socket.SHUT_RDWR)
                
            except (OSError, socket.error):
                pass
                
            finally:
                conn.close()
    
    def _test_server_run_udp(self) -> None:
        """UDP测试服务器运行"""
        while self.sock and self.sock.fileno() != -1:
            try:
                msg, addr = self.sock.recvfrom(self.buff_size)
                Logger.debug("fwd-test: got client %s" % (addr,))
                self.sock.sendto(b"It works! - Natter\r\n", addr)
                
            except (OSError, socket.error):
                return
    
    def stop_forward(self) -> None:
        """停止转发"""
        if self.sock:
            Logger.debug("fwd-test: Stopping test server")
            self.sock.close()
            self.sock = None


class ForwardSocket(object):
    """Socket转发类"""
    
    def __init__(self):
        self.sock = None
        self.buff_size = 8192
        self.timeout = 3
        self.max_threads = 1000
    
    def __del__(self):
        self.stop_forward()
    
    def start_forward(self, ip: str, port: int, toip: str, toport: int, udp: bool = False) -> None:
        """启动转发"""
        sock_type = socket.SOCK_DGRAM if udp else socket.SOCK_STREAM
        self.sock = socket.socket(socket.AF_INET, sock_type)
        
        try:
            socket_set_opt(
                self.sock,
                reuse       = True,
                bind_addr   = (ip, port)
            )
            
            Logger.debug("fwd-socket: Starting socket forwarding from %s to %s" % (
                addr_to_uri((ip, port), udp=udp), addr_to_uri((toip, toport), udp=udp)
            ))
            
            if udp:
                th = start_daemon_thread(self._socket_udp_recvfrom, args=(toip, toport))
            else:
                th = start_daemon_thread(self._socket_tcp_listen, args=(toip, toport))
                
            time.sleep(1)
            if not th.is_alive():
                raise OSError("Socket forwarding thread exited too quickly")
                
        except Exception:
            self.sock.close()
            self.sock = None
            raise
    
    def _socket_tcp_listen(self, toip: str, toport: int) -> None:
        """TCP监听"""
        self.sock.listen(5)
        while self.sock and self.sock.fileno() != -1:
            try:
                conn, addr = self.sock.accept()
                Logger.debug("fwd-socket: got client %s" % (addr,))
                
            except (OSError, socket.error):
                return
                
            try:
                sock_to = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock_to.connect((toip, toport))
                
            except (OSError, socket.error):
                conn.close()
                continue
                
            start_daemon_thread(self._socket_forward, args=(conn, sock_to))
            start_daemon_thread(self._socket_forward, args=(sock_to, conn))
    
    def _socket_udp_recvfrom(self, toip: str, toport: int) -> None:
        """UDP接收"""
        outbound_socks = {}
        while self.sock and self.sock.fileno() != -1:
            try:
                buff, addr = self.sock.recvfrom(self.buff_size)
                s = outbound_socks.get(addr)
                
            except (OSError, socket.error):
                return
                
            try:
                if not s:
                    s = outbound_socks[addr] = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.settimeout(self.udp_timeout)
                    s.connect((toip, toport))
                    
                    if threading.active_count() >= self.max_threads:
                        raise OSError("Too many threads")
                        
                    start_daemon_thread(self._socket_forward, args=(self.sock, s, addr))
                    
                if buff:
                    s.send(buff)
                else:
                    s.close()
                    del outbound_socks[addr]
                    
            except (OSError, socket.error):
                if addr in outbound_socks:
                    outbound_socks[addr].close()
                    del outbound_socks[addr]
                continue
    
    def _socket_forward(self, sock_to_recv: socket.socket, sock_to_send: socket.socket, addr: Optional[Tuple[str, int]] = None) -> None:
        """Socket转发"""
        try:
            while sock_to_recv.fileno() != -1 and sock_to_send.fileno() != -1:
                buff = sock_to_recv.recv(self.buff_size)
                if buff and sock_to_send.fileno() != -1:
                    if addr:
                        sock_to_send.sendto(buff, addr)
                    else:
                        sock_to_send.sendall(buff)
                else:
                    sock_to_recv.close()
                    sock_to_send.close()
                    return
                    
        except (OSError, socket.error):
            sock_to_recv.close()
            sock_to_send.close()
            return
    
    def stop_forward(self) -> None:
        """停止转发"""
        if self.sock:
            Logger.debug("fwd-socket: Stopping socket")
            self.sock.close()
            self.sock = None


class ForwardNone(object):
    """空转发类"""
    
    def start_forward(self, ip: str, port: int, toip: str, toport: int, udp: bool = False) -> None:
        """启动转发"""
        pass
    
    def stop_forward(self) -> None:
        """停止转发"""
        pass
