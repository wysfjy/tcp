#!/usr/bin/env python3
"""
端口测试类
"""

import os
import sys
import json
import socket
import requests
from typing import Tuple, Optional

from utils import Logger, socket_set_opt, addr_to_str, addr_to_uri


class PortTest(object):
    """端口测试类"""
    
    def test_lan(self, addr: Tuple[str, int], source_ip: Optional[str] = None, 
                 interface: Optional[str] = None, info: bool = False) -> int:
        """测试LAN端口"""
        print_status = Logger.info if info else Logger.debug
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            socket_set_opt(
                sock,
                bind_addr   = (source_ip, 0) if source_ip else None,
                interface   = interface,
                timeout     = 1
            )
            
            if sock.connect_ex(addr) == 0:
                print_status("LAN > %-21s [ OPEN ]" % addr_to_str(addr))
                return 1
            else:
                print_status("LAN > %-21s [ CLOSED ]" % addr_to_str(addr))
                return -1
                
        except (OSError, socket.error) as ex:
            print_status("LAN > %-21s [ UNKNOWN ]" % addr_to_str(addr))
            Logger.debug("Cannot test port %s from LAN because: %s" % (addr_to_str(addr), ex))
            return 0
            
        finally:
            sock.close()
    
    def test_wan(self, addr: Tuple[str, int], source_ip: Optional[str] = None, 
                 interface: Optional[str] = None, info: bool = False) -> int:
        """测试WAN端口"""
        # only port number in addr is used, WAN IP will be ignored
        print_status = Logger.info if info else Logger.debug
        
        ret01 = self._test_ifconfigco(addr[1], source_ip, interface)
        if ret01 == 1:
            print_status("WAN > %-21s [ OPEN ]" % addr_to_str(addr))
            return 1
            
        ret02 = self._test_transmission(addr[1], source_ip, interface)
        if ret02 == 1:
            print_status("WAN > %-21s [ OPEN ]" % addr_to_str(addr))
            return 1
            
        if ret01 == ret02 == -1:
            print_status("WAN > %-21s [ CLOSED ]" % addr_to_str(addr))
            return -1
            
        print_status("WAN > %-21s [ UNKNOWN ]" % addr_to_str(addr))
        return 0
    
    def _test_ifconfigco(self, port: int, source_ip: Optional[str] = None, 
                        interface: Optional[str] = None) -> int:
        """通过ifconfig.co测试端口"""
        # repo: https://github.com/mpolden/echoip
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            socket_set_opt(
                sock,
                bind_addr   = (source_ip, 0) if source_ip else None,
                interface   = interface,
                timeout     = 8
            )
            
            sock.connect(("ifconfig.co", 80))
            sock.sendall((
                "GET /port/%d HTTP/1.0\r\n"
                "Host: ifconfig.co\r\n"
                "User-Agent: curl/8.0.0 (Natter)\r\n"
                "Accept: */*\r\n"
                "Connection: close\r\n"
                "\r\n" % port
            ).encode())
            
            response = b""
            while True:
                buff = sock.recv(4096)
                if not buff:
                    break
                response += buff
                
            Logger.debug("port-test: ifconfig.co: %s" % response)
            _, content = response.split(b"\r\n\r\n", 1)
            dat = json.loads(content.decode())
            return 1 if dat["reachable"] else -1
            
        except (OSError, LookupError, ValueError, TypeError, socket.error) as ex:
            Logger.debug("Cannot test port %d from ifconfig.co because: %s" % (port, ex))
            return 0
            
        finally:
            sock.close()
    
    def _test_transmission(self, port: int, source_ip: Optional[str] = None, 
                          interface: Optional[str] = None) -> int:
        """通过transmission测试端口"""
        # repo: https://github.com/transmission/portcheck
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            socket_set_opt(
                sock,
                bind_addr   = (source_ip, 0) if source_ip else None,
                interface   = interface,
                timeout     = 8
            )
            
            sock.connect(("portcheck.transmissionbt.com", 80))
            sock.sendall((
                "GET /%d HTTP/1.0\r\n"
                "Host: portcheck.transmissionbt.com\r\n"
                "User-Agent: curl/8.0.0 (Natter)\r\n"
                "Accept: */*\r\n"
                "Connection: close\r\n"
                "\r\n" % port
            ).encode())
            
            response = b""
            while True:
                buff = sock.recv(4096)
                if not buff:
                    break
                response += buff
                
            Logger.debug("port-test: portcheck.transmissionbt.com: %s" % response)
            _, content = response.split(b"\r\n\r\n", 1)
            
            if content.strip() == b"1":
                return 1
            elif content.strip() == b"0":
                return -1
            
            raise ValueError("Unexpected response: %s" % response)
            
        except (OSError, LookupError, ValueError, TypeError, socket.error) as ex:
            Logger.debug(
                "Cannot test port %d from portcheck.transmissionbt.com "
                "because: %s" % (port, ex)
            )
            return 0
            
        finally:
            sock.close()
