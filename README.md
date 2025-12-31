# Cloudflare DNS 更新说明

## 配置说明

在 `config.json` 文件中需要配置以下 Cloudflare API 参数：

```json
{
    "cloudflare": {
        "api_token": "your_cloudflare_api_token",
        "zone_id": "your_zone_id"
    },
    "domains": {
        "yuan": "your_yuan_domain",
        "mc": "your_mc_domain"
    }
}
```

## 功能说明

1. **更新 your_yuan_domain 的 A 记录**
   - A 记录：IPv4 地址

2. **更新 your_mc_domain 的 SRV 记录**
   - 服务类型：minecraft
   - 协议：tcp
   - 优先级：0
   - 权重：5
   - 端口：25565
   - 目标：your_yuan_domain

## 使用方法

1. 替换 `your_cloudflare_api_token` 和 `your_zone_id` 为实际的 Cloudflare API 令牌和区域 ID
2. 替换 `your_yuan_domain` 和 `your_mc_domain` 为实际的域名
3. 运行脚本：`python creat.py`

## 注意事项

- 确保 Cloudflare API 令牌具有 DNS 编辑权限
- 确保域名已经在 Cloudflare 中托管
- SRV 记录格式为：`_service._proto.name`