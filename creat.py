import json
import time
from typing import Dict, List, Tuple

import threading
import socket
import select
import requests

# 读取配置文件
import json
with open('config.json', 'r') as f:
    config = json.load(f)

CF_API_TOKEN = config['cloudflare']['api_token']
CF_ZONE_ID = config['cloudflare']['zone_id']
CF_BASE_URL = "https://api.cloudflare.com/client/v4/zones"

# 域名配置
DOMAIN_YUAN = config['domains']['yuan']
DOMAIN_MC = config['domains']['mc']

def forward_ipv6(port,to_port):
    """在独立线程中将 IPv6 的 19847 端口流量转发到 19832 端口，不影响 IPv4"""
    listen_addr = ('::', int(port), 0, 0)   # IPv6 任意地址
    target_addr = ('::1', int(to_port), 0, 0)  # IPv6 本地回环

    # 创建 IPv6 TCP socket
    server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(listen_addr)
    server.listen(5)

    while True:
        client, addr = server.accept()
        # 为每个连接单独开线程，实现并发
        threading.Thread(target=handle_forward, args=(client, target_addr), daemon=True).start()

def handle_forward(client, target_addr):
    """处理单个连接的转发"""
    try:
        remote = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        remote.connect(target_addr)

        # 双向转发
        sockets = [client, remote]
        while True:
            r, _, _ = select.select(sockets, [], [])
            if client in r:
                data = client.recv(4096)
                if not data:
                    break
                remote.sendall(data)
            if remote in r:
                data = remote.recv(4096)
                if not data:
                    break
                client.sendall(data)
    except Exception:
        pass
    finally:
        client.close()
        remote.close()

# 启动 IPv6 转发线程，不阻塞主线程
def create_forward_ipv6(port,to_port):
    threading.Thread(target=forward_ipv6, args=(port,to_port), daemon=True).start()

def update_dns_record(record_type, name, content, ttl=1, proxied=False):
    """更新 Cloudflare DNS 记录"""
    url = f"{CF_BASE_URL}/{CF_ZONE_ID}/dns_records"
    headers = {
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json"
    }
    
    # 查找现有记录
    params = {"type": record_type, "name": name}
    response = requests.get(url, headers=headers, params=params)
    response.raise_for_status()
    
    data = response.json()
    if data["result"]:
        # 更新现有记录
        record_id = data["result"][0]["id"]
        update_url = f"{url}/{record_id}"
        payload = {
            "type": record_type,
            "name": name,
            "content": content,
            "ttl": ttl,
            "proxied": proxied
        }
        update_response = requests.put(update_url, headers=headers, json=payload)
        update_response.raise_for_status()
        print(f"成功更新 {record_type} 记录: {name}")
    else:
        # 创建新记录
        payload = {
            "type": record_type,
            "name": name,
            "content": content,
            "ttl": ttl,
            "proxied": proxied
        }
        create_response = requests.post(url, headers=headers, json=payload)
        try:
            create_response.raise_for_status()
            print(f"成功创建 {record_type} 记录: {name}")
        except requests.exceptions.HTTPError as e:
            print(f"创建 {record_type} 记录失败: {e}")
            print(f"响应内容: {create_response.text}")

def update_srv_record(name, service, proto, priority, weight, port, target):
    """更新 Cloudflare SRV 记录"""
    url = f"{CF_BASE_URL}/{CF_ZONE_ID}/dns_records"
    headers = {
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json"
    }
    
    # SRV 记录格式: _service._proto.name
    full_name = f"_{service}._{proto}.{name}"
    
    # 查找现有记录
    params = {"type": "SRV", "name": full_name}
    response = requests.get(url, headers=headers, params=params)
    response.raise_for_status()
    
    data = response.json()
    if data["result"]:
        # 更新现有记录
        record_id = data["result"][0]["id"]
        update_url = f"{url}/{record_id}"
        payload = {
            "type": "SRV",
            "name": full_name,
            "data": {
                "service": service,
                "proto": proto,
                "name": name,
                "priority": priority,
                "weight": weight,
                "port": port,
                "target": target
            },
            "ttl": 1,
            "proxied": False
        }
        update_response = requests.put(update_url, headers=headers, json=payload)
        update_response.raise_for_status()
        print(f"成功更新 SRV 记录: {full_name}")
    else:
        # 创建新记录
        payload = {
            "type": "SRV",
            "name": full_name,
            "data": {
                "service": service,
                "proto": proto,
                "name": name,
                "priority": priority,
                "weight": weight,
                "port": port,
                "target": target
            },
            "ttl": 1,
            "proxied": False
        }
        create_response = requests.post(url, headers=headers, json=payload)
        try:
            create_response.raise_for_status()
            print(f"成功创建 SRV 记录: {full_name}")
        except requests.exceptions.HTTPError as e:
            print(f"创建 SRV 记录失败: {e}")
            print(f"响应内容: {create_response.text}")

def creat():
    requests.get("http://127.0.0.1:3319/start/25565")
    time.sleep(20)
    shangbao = requests.get("http://127.0.0.1:3319/shangbao").text
    print(f"上报内容: {shangbao}")
    
    # 解析JSON格式的上报内容
    try:
        import json
        shangbao_data = json.loads(shangbao.replace("'", '"'))
        if "25565" in shangbao_data:
            ip_port = shangbao_data["25565"]
            if ":" in ip_port:
                ipv4_address, port = ip_port.split(":")
                ipv4_address = ipv4_address.strip()
                port = port.strip()
                
                print(f"解析到IPv4: {ipv4_address}, 端口: {port}")
                
                # 更新 your_yuan_domain 的 A 记录
                update_dns_record("A", DOMAIN_YUAN, ipv4_address)
                 
                # 更新 your_mc_domain 的 SRV 记录
                update_srv_record(DOMAIN_MC, "minecraft", "tcp", 0, 5, port, DOMAIN_YUAN)
            else:
                print("解析失败: IP和端口格式不正确")
        else:
            print("解析失败: 没有找到25565端口的数据")
    except json.JSONDecodeError as e:
        print(f"JSON解析失败: {e}")
    
creat()