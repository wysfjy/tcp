import json
import time
import json
import requests
from mcstatus import JavaServer

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
    a = requests.get("http://127.0.0.1:3319/shangbao")
    shangbao = a.text
    print(f"上报内容: {shangbao}")
    
    # 解析JSON格式的上报内容
    try:
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
def test(shangbao, i = 0):
    try:
        server = JavaServer.lookup(shangbao["25565"])
        print(server.ping())
    except TimeoutError:
        print(f"测试失败")
        if i < 10:
            time.sleep(5)
            test(shangbao, i + 1)
        else:
            requests.get(f"http://127.0.0.1:3319/stop")
            creat()
            time.sleep(60)
            return
    except Exception as e:
        print(f"测试失败: {e}")
        requests.get(f"http://127.0.0.1:3319/stop")
        time.sleep(60)
        creat()
        time.sleep(60)
        return

creat()
time.sleep(10)
while True:
    shangbao = requests.get("http://127.0.0.1:3319/shangbao")
    shangbao = shangbao.text
    shangbao = json.loads(shangbao.replace("'", '"'))
    test(shangbao)
    time.sleep(1)