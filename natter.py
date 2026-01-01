#!/usr/bin/env python3

import os
import sys
import json
import time
import errno
import atexit
import random
import signal
import socket
import struct
import argparse
import threading
import subprocess
import requests

__version__ = "2.2.1"

class ForwardTestServer(object):
    def __init__(self):
        self.sock = None
        self.buff_size = 8192
        self.timeout = 3

    def __del__(self):
        self.stop_forward()

    # Start a socket server for testing purpose
    # target address is ignored
    def start_forward(self, ip, port, toip, toport, udp=False):
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

    def _test_server_run_http(self):
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

    def _test_server_run_udp(self):
        while self.sock and self.sock.fileno() != -1:
            try:
                msg, addr = self.sock.recvfrom(self.buff_size)
                Logger.debug("fwd-test: got client %s" % (addr,))
                self.sock.sendto(b"It works! - Natter\r\n", addr)
            except (OSError, socket.error):
                return

    def stop_forward(self):
        if self.sock:
            Logger.debug("fwd-test: Stopping test server")
            self.sock.close()
            self.sock = None

def check_docker_network():
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

class PortTest(object):
    def test_lan(self, addr, source_ip=None, interface=None, info=False):
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

    def test_wan(self, addr, source_ip=None, interface=None, info=False):
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

    def _test_ifconfigco(self, port, source_ip=None, interface=None):
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

    def _test_transmission(self, port, source_ip=None, interface=None):
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

class NatterExit(object):
    atexit.register(lambda : NatterExit._atexit[0]())
    _atexit = [lambda : None]

    @staticmethod
    def set_atexit(func):
        NatterExit._atexit[0] = func

class NatterExitException(Exception):
    pass


class NatterRetryException(Exception):
    pass

def addr_to_str(addr):
    return "%s:%d" % addr


class Logger(object):
    DEBUG = 0
    INFO  = 1
    WARN  = 2
    ERROR = 3
    rep = {DEBUG: "D", INFO: "I", WARN: "W", ERROR: "E"}
    level = INFO
    
    @staticmethod
    def set_level(level):
        Logger.level = level

    @staticmethod
    def get_timestr():
        return "%04d-%02d-%02d %02d:%02d:%02d" % time.localtime()[:6]

    @staticmethod
    def debug(text=""):
        if Logger.level <= Logger.DEBUG:
            sys.stderr.write(("%s [%s] %s\n") % (
                Logger.get_timestr(), Logger.rep[Logger.DEBUG], text
            ))

    @staticmethod
    def info(text=""):
        if Logger.level <= Logger.INFO:
            sys.stderr.write(("%s [%s] %s\n") % (
                Logger.get_timestr(), Logger.rep[Logger.INFO], text
            ))

    @staticmethod
    def warning(text=""):
        if Logger.level <= Logger.WARN:
            sys.stderr.write(("%s [%s] %s\n") % (
                Logger.get_timestr(), Logger.rep[Logger.WARN], text
            ))

    @staticmethod
    def error(text=""):
        if Logger.level <= Logger.ERROR:
            sys.stderr.write(("%s [%s] %s\n") % (
                Logger.get_timestr(), Logger.rep[Logger.ERROR], text
            ))


class StunClient(object):
    class ServerUnavailable(Exception):
        pass

    def __init__(self, stun_server_list, source_host="0.0.0.0", source_port=0,
                 interface=None, udp=False):
        if not stun_server_list:
            raise ValueError("STUN server list is empty")
        self.stun_server_list = stun_server_list
        self.source_host = source_host
        self.source_port = source_port
        self.interface = interface
        self.udp = udp

    def get_mapping(self):
        first = self.stun_server_list[0]
        while True:
            if self.source_port:
                set_reuse_port(self.source_port)
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

    def _get_mapping(self):
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


class KeepAlive(object):
    def __init__(self, host, port, source_host, source_port, interface=None, udp=False):
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

    def _connect(self):
        sock_type = socket.SOCK_DGRAM if self.udp else socket.SOCK_STREAM
        self.sock = socket.socket(socket.AF_INET, sock_type)
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

    def keep_alive(self):
        if self.sock is None:
            self._connect()
        if self.udp:
            self._keep_alive_udp()
        else:
            self._keep_alive_tcp()
        Logger.debug("keep-alive: OK")

    def disconnect(self):
        if self.sock is not None:
            self.sock.close()
            self.sock = None
            self.reconn = True

    def _keep_alive_tcp(self):
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

    def _keep_alive_udp(self):
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


class ForwardSocket(object):
    def __init__(self):
        self.sock = None
        self.buff_size = 8192
        self.timeout = 3
        self.max_threads = 1000

    def __del__(self):
        self.stop_forward()

    def start_forward(self, ip, port, toip, toport, udp=False):
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

    def _socket_tcp_listen(self, toip, toport):
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

    def _socket_udp_recvfrom(self, toip, toport):
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

    def _socket_forward(self, sock_to_recv, sock_to_send, addr=None):
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

    def stop_forward(self):
        if self.sock:
            Logger.debug("fwd-socket: Stopping socket")
            self.sock.close()
            self.sock = None


class ForwardNone(object):
    def start_forward(self, ip, port, toip, toport, udp=False):
        pass

    def stop_forward(self):
        pass


def socket_set_opt(sock, reuse=False, bind_addr=None, interface=None, timeout=-1):
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


def start_daemon_thread(target, args=()):
    th = threading.Thread(target=target, args=args)
    th.daemon = True
    th.start()
    return th


def addr_to_uri(addr, udp=False, a=0):
    if a == 0:
        if udp:
            return "udp://%s:%d" % addr
        else:
            return "tcp://%s:%d" % addr
    else:
            return "%s:%d" % addr


def validate_ip(s, err=True):
    try:
        socket.inet_aton(s)
        return True
    except (OSError, socket.error):
        if err:
            raise ValueError("Invalid IP address: %s" % s)
        return False


def validate_port(s, err=True):
    if str(s).isdigit() and int(s) in range(65536):
        return True
    if err:
        raise ValueError("Invalid port number: %s" % s)
    return False


def validate_addr_str(s, err=True):
    l = str(s).split(":", 1)
    if len(l) == 1:
        return True
    return validate_port(l[1], err)


def validate_positive(s, err=True):
    if str(s).isdigit() and int(s) > 0:
        return True
    if err:
        raise ValueError("Not a positive integer: %s" % s)
    return False


def ip_normalize(ipaddr):
    return socket.inet_ntoa(socket.inet_aton(ipaddr))


def set_reuse_port(port):
    pass


def natter_main(show_title = True):
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

    validate_positive(interval)
    if stun_list:
        for stun_srv in stun_list:
            validate_addr_str(stun_srv)
    validate_addr_str(keepalive_srv)
    if notify_sh:
        validate_filepath(notify_sh)
    if not validate_ip(bind_ip, err=False):
        bind_interface = bind_ip
        bind_ip = "0.0.0.0"
    validate_port(bind_port)
    validate_ip(to_ip)
    validate_port(to_port)

    # Normalize IPv4 in dotted-decimal notation
    #   e.g. 10.1 -> 10.0.0.1
    bind_ip = ip_normalize(bind_ip)
    to_ip = ip_normalize(to_ip)

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

    if not keepalive_srv:
        keepalive_srv = "www.baidu.com"
        if udp_mode:
            keepalive_srv = "119.29.29.29"

    stun_srv_list = []
    for item in stun_list:
        l = item.split(":", 2) + ["3478"]
        stun_srv_list.append((l[0], int(l[1])),)

    if udp_mode:
        l = keepalive_srv.split(":", 2) + ["53"]
        keepalive_host, keepalive_port = l[0], int(l[1])
    else:
        l = keepalive_srv.split(":", 2) + ["80"]
        keepalive_host, keepalive_port = l[0], int(l[1])

    # forward method defaults
    if not method:
        if to_ip == "0.0.0.0" and to_port == 0 and \
                bind_ip == "0.0.0.0" and bind_port == 0 and bind_interface is None:
            method = "test"
        elif to_ip == "0.0.0.0" and to_port == 0:
            method = "none"
        else:
            method = "socket"

    if method == "none":
        ForwardImpl = ForwardNone
    elif method == "test":
        ForwardImpl = ForwardTestServer
    elif method == "iptables":
        ForwardImpl = ForwardIptables
    elif method == "sudo-iptables":
        ForwardImpl = ForwardSudoIptables
    elif method == "iptables-snat":
        ForwardImpl = ForwardIptablesSnat
    elif method == "sudo-iptables-snat":
        ForwardImpl = ForwardSudoIptablesSnat
    elif method == "nftables":
        ForwardImpl = ForwardNftables
    elif method == "sudo-nftables":
        ForwardImpl = ForwardSudoNftables
    elif method == "nftables-snat":
        ForwardImpl = ForwardNftablesSnat
    elif method == "sudo-nftables-snat":
        ForwardImpl = ForwardSudoNftablesSnat
    elif method == "socat":
        ForwardImpl = ForwardSocat
    elif method == "gost":
        ForwardImpl = ForwardGost
    elif method == "socket":
        ForwardImpl = ForwardSocket
    else:
        raise ValueError("Unknown method name: %s" % method)
    #
    #  Natter
    #
    if show_title:
        Logger.info("Natter v%s" % __version__)
        if len(sys.argv) == 1:
            Logger.info("Tips: Use `--help` to see help messages")

    check_docker_network()

    forwarder = ForwardImpl()
    port_test = PortTest()

    stun = StunClient(stun_srv_list, bind_ip, bind_port, udp=udp_mode, interface=bind_interface)
    natter_addr, outer_addr = stun.get_mapping()
    # set actual ip and port for keep-alive socket to bind, instead of zero
    bind_ip, bind_port = natter_addr

    keep_alive = KeepAlive(keepalive_host, keepalive_port, bind_ip, bind_port, udp=udp_mode, interface=bind_interface)
    keep_alive.keep_alive()

    # get the mapped address again after the keep-alive connection is established
    outer_addr_prev = outer_addr
    natter_addr, outer_addr = stun.get_mapping()
    if outer_addr != outer_addr_prev:
        Logger.warning("Network is unstable, or not full cone")

    # set actual ip of localhost for correct forwarding
    if socket.inet_aton(to_ip) in [socket.inet_aton("127.0.0.1"), socket.inet_aton("0.0.0.0")]:
        to_ip = natter_addr[0]

    # if not specified, the target port is set to be the same as the outer port
    if not to_port:
        to_port = outer_addr[1]

    # some exceptions: ForwardNone and ForwardTestServer are not real forward methods,
    # so let target ip and port equal to natter's
    if ForwardImpl in (ForwardNone, ForwardTestServer):
        to_ip, to_port = natter_addr

    to_addr = (to_ip, to_port)
    forwarder.start_forward(natter_addr[0], natter_addr[1], to_addr[0], to_addr[1], udp=udp_mode)
    NatterExit.set_atexit(forwarder.stop_forward)

    # UPnP
    upnp = None
    upnp_router = None
    upnp_ready = False

    if upnp_enabled:
        upnp = UPnPClient(bind_ip=natter_addr[0], interface=bind_interface)
        Logger.info()
        Logger.info("Scanning UPnP Devices...")
        try:
            upnp_router = upnp.discover_router()
        except (OSError, socket.error, ValueError) as ex:
            Logger.error("upnp: failed to discover router: %s" % ex)

    if upnp_router:
        Logger.info("[UPnP] Found router %s" % upnp_router.ipaddr)
        try:
            upnp.forward("", bind_port, bind_ip, bind_port, udp=udp_mode, duration=interval*3)
        except (OSError, socket.error, ValueError) as ex:
            Logger.error("upnp: failed to forward port: %s" % ex)
        else:
            upnp_ready = True

    # Display route information
    Logger.info()
    route_str = ""
    if ForwardImpl not in (ForwardNone, ForwardTestServer):
        route_str += "%s <--%s--> " % (addr_to_uri(to_addr, udp=udp_mode), method)
    route_str += "%s <--Natter--> %s" % (
        addr_to_uri(natter_addr, udp=udp_mode), addr_to_uri(outer_addr, udp=udp_mode)
    )
    Logger.info(route_str)
    requests.get(url=f"http://127.0.0.1:3319/shangbao/{addr_to_uri(outer_addr, udp=udp_mode, a=1)}/{to_addr[1]}/1")
    Logger.info()

    # Test mode notice
    if ForwardImpl == ForwardTestServer:
        Logger.info("Test mode in on.")
        Logger.info("Please check [ %s://%s ]" % ("udp" if udp_mode else "http", addr_to_str(outer_addr)))
        Logger.info()

    # Call notification script
    if notify_sh:
        protocol = "udp" if udp_mode else "tcp"
        inner_ip, inner_port = to_addr if method else natter_addr
        outer_ip, outer_port = outer_addr
        Logger.info("Calling script: %s" % notify_sh)
        subprocess.call([
            os.path.abspath(notify_sh), protocol, str(inner_ip), str(inner_port), str(outer_ip), str(outer_port)
        ], shell=False)

    # Display check results, TCP only
    if not udp_mode:
        ret1 = port_test.test_lan(to_addr, info=True)
        ret2 = port_test.test_lan(natter_addr, info=True)
        ret3 = port_test.test_lan(outer_addr, source_ip=natter_addr[0], interface=bind_interface, info=True)
        ret4 = port_test.test_wan(outer_addr, source_ip=natter_addr[0], interface=bind_interface, info=True)
        if ret1 == -1:
            Logger.warning("!! Target port is closed !!")
        elif ret1 == 1 and ret3 == ret4 == -1:
            Logger.warning("!! Hole punching failed !!")
        elif ret3 == 1 and ret4 == -1:
            Logger.warning("!! You may be behind a firewall !!")
        elif ret3 == -1 and ret4 == 1:
            Logger.warning("!! You may can't use auto retry when network is unstable !!")
            requests.get(url=f"http://127.0.0.1:3319/shangbao/{addr_to_uri(outer_addr, udp=udp_mode, a=1)}/{to_addr[1]}/0")
        Logger.info()
        # retry
        if keep_retry and ret1 == -1:
            Logger.info("Retry after %d seconds..." % interval)
            time.sleep(interval)
            forwarder.stop_forward()
            keep_alive.disconnect()
            raise NatterRetryException("Target port is closed")
    #
    #  Main loop
    #
    need_recheck = False
    cnt = 0
    while True:
        # force recheck every 20th loop
        cnt = (cnt + 1) % 20
        if cnt == 0:
            need_recheck = True
        if need_recheck:
            Logger.debug("Start recheck")
            need_recheck = False
            # check LAN port first
            if udp_mode or port_test.test_lan(outer_addr, source_ip=natter_addr[0], interface=bind_interface) == -1:
                # then check through STUN
                _, outer_addr_curr = stun.get_mapping()
                if outer_addr_curr != outer_addr:
                    forwarder.stop_forward()
                    keep_alive.disconnect()
                    # exit or retry
                    if exit_when_changed:
                        Logger.info("Natter is exiting because mapped address has changed")
                        raise NatterExitException("Mapped address has changed")
                    raise NatterRetryException("Mapped address has changed")
        # end of recheck
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
        if upnp_ready:
            try:
                upnp.renew()
            except (OSError, socket.error) as ex:
                Logger.error("upnp: failed to renew upnp: %s" % ex)
        sleep_sec = interval - (time.time() - ts)
        if sleep_sec > 0:
            time.sleep(sleep_sec)


def main():
    signal.signal(signal.SIGTERM, lambda s,f: sys.exit(143))
    try:
        natter_main()
    except KeyboardInterrupt:
        sys.exit()


if __name__ == "__main__":
    main()