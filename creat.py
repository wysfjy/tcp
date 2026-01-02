import json
import time
import requests
from mcstatus import JavaServer
from typing import Dict, Optional

# 读取配置文件
with open('config.json', 'r') as f:
    config = json.load(f)

# Cloudflare 配置
CF_API_TOKEN: str = config['cloudflare']['api_token']
CF_ZONE_ID: str = config['cloudflare']['zone_id']
CF_BASE_URL: str = "https://api.cloudflare.com/client/v4/zones"

# 域名配置
DOMAIN_YUAN: str = config['domains']['yuan']
DOMAIN_MC: str = config['domains']['mc']

def update_dns_record(record_type: str, name: str, content: str, ttl: int = 1, proxied: bool = False) -> None:
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
    payload = {
        "type": record_type,
        "name": name,
        "content": content,
        "ttl": ttl,
        "proxied": proxied
    }
    
    if data["result"]:
        # 更新现有记录
        record_id = data["result"][0]["id"]
        update_url = f"{url}/{record_id}"
        update_response = requests.put(update_url, headers=headers, json=payload)
        update_response.raise_for_status()
        print(f"成功更新 {record_type} 记录: {name}")
    else:
        # 创建新记录
        create_response = requests.post(url, headers=headers, json=payload)
        try:
            create_response.raise_for_status()
            print(f"成功创建 {record_type} 记录: {name}")
        except requests.exceptions.HTTPError as e:
            print(f"创建 {record_type} 记录失败: {e}")
            print(f"响应内容: {create_response.text}")

def update_srv_record(name: str, service: str, proto: str, priority: int, weight: int, port: int, target: str) -> None:
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
    
    if data["result"]:
        # 更新现有记录
        record_id = data["result"][0]["id"]
        update_url = f"{url}/{record_id}"
        update_response = requests.put(update_url, headers=headers, json=payload)
        update_response.raise_for_status()
        print(f"成功更新 SRV 记录: {full_name}")
    else:
        # 创建新记录
        create_response = requests.post(url, headers=headers, json=payload)
        try:
            create_response.raise_for_status()
            print(f"成功创建 SRV 记录: {full_name}")
        except requests.exceptions.HTTPError as e:
            print(f"创建 SRV 记录失败: {e}")
            print(f"响应内容: {create_response.text}")

def parse_shangbao(shangbao: str) -> None:
    """解析上报内容并更新 DNS 记录"""
    try:
        shangbao_data: Dict[str, str] = json.loads(shangbao.replace("'", '"'))
        
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
                update_srv_record(DOMAIN_MC, "minecraft", "tcp", 0, 5, int(port), DOMAIN_YUAN)
            else:
                print("解析失败: IP和端口格式不正确")
        else:
            print("解析失败: 没有找到25565端口的数据")
    except json.JSONDecodeError as e:
        print(f"JSON解析失败: {e}")

def creat() -> None:
    """启动 Minecraft 服务器并更新 DNS 记录"""
    try:
        requests.get("http://127.0.0.1:3319/start/25565", timeout=5)
    except requests.exceptions.RequestException as e:
        print(f"无法连接到服务器: {e}")
        return
    # 等待服务器上报数据，最多等待60秒
    wait_time = 0
    max_wait = 60
    shangbao = ""
    while wait_time < max_wait:
        try:
            response = requests.get("http://127.0.0.1:3319/shangbao", timeout=3)
            if response.status_code == 200 and response.text:
                shangbao = response.text
                if "25565" in shangbao:
                    break
        except requests.exceptions.RequestException:
            pass
        time.sleep(5)
        wait_time +=5
    if wait_time >= max_wait:
        print("等待服务器上报数据超时")
        return
      
    print(f"上报内容: {shangbao}")
    parse_shangbao(shangbao)
def test(i: int = 0) -> None:
    """测试 Minecraft 服务器连接"""
    # 每次测试前重新获取最新的上报数据
    try:
        response = requests.get("http://127.0.0.1:3319/shangbao")
        shangbao_text = response.text
        shangbao_data: Dict[str, str] = json.loads(shangbao_text.replace("'", '"'))
        
        if "25565" not in shangbao_data:
            print("测试失败: 没有找到25565端口的数据")
            if i <10:
                time.sleep(5)
                test(i+1)
            else:
                print("重试次数过多，重启服务器...")
                requests.get(f"http://127.0.0.1:3319/stop")
                creat()
                time.sleep(60)
                test()
            return
        
        server = JavaServer.lookup(shangbao_data["25565"])
        latency = server.ping(timeout=5)
        print(f"服务器连接成功，延迟: {latency}ms")
    except TimeoutError:
        print(f"测试失败: 连接超时")
        if i < 10:
            time.sleep(5)
            test(i + 1)
        else:
            print("重试次数过多，重启服务器...")
            requests.get(f"http://127.0.0.1:3319/stop")
            creat()
            time.sleep(60)
            test()
    except json.JSONDecodeError as e:
        print(f"JSON解析失败: {e}")
        if i <10:
            time.sleep(5)
            test(i+1)
        else:
            print("重试次数过多，重启服务器...")
            requests.get(f"http://127.0.0.1:3319/stop")
            creat()
            time.sleep(60)
            test()
    except Exception as e:
        print(f"测试失败: {e}")
        requests.get(f"http://127.0.0.1:3319/stop")
        time.sleep(60)
        creat()
        time.sleep(60)
        test()

def main() -> None:
    """主函数"""
    creat()
    time.sleep(30)
    
    status = requests.get("http://127.0.0.1:3319/shangbao/25565").text
    
    if status == "ok":
        print("服务器启动成功，开始监控...")
        while True:
            test()
            time.sleep(60)
    else:
        print(f"服务器启动出错: {status}")

if __name__ == "__main__":
    main()