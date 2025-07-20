import requests
from fastmcp import FastMCP

# 初始化Virustotal MCP
mcp = FastMCP('Virustotal MCP')

# 请在此处填写Virustotal API Key
api_key = "xxxxxxxxx"


def make_api_request(endpoint, value):
    """
    向 VirusTotal API 发送请求并返回 JSON Response。
    """

    BASE_URL = "https://www.virustotal.com/api/v3"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    url = f"{BASE_URL}/{endpoint}/{value}"

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # 如果请求失败，则抛出HTTPError
        return response.json()
    except requests.exceptions.HTTPError as e:
        print(f"HTTP 错误: {e.response.status_code} - {e.response.text}")
    except requests.exceptions.ConnectionError as e:
        print(f"连接错误: {e}")
    except requests.exceptions.Timeout as e:
        print(f"请求超时: {e}")
    except requests.exceptions.RequestException as e:
        print(f"请求发生错误: {e}")
    return None

@mcp.tool
async def get_file_report(file_hash: str):
    """获取文件报告"""
    report = make_api_request("files", file_hash)
    if report:
        return report

@mcp.tool
async def get_ip_report(ip_address: str):
    """获取 IP 地址报告"""
    report = make_api_request("ip_addresses", ip_address)
    if report:
        return report

@mcp.tool
async def get_domain_report(domain: str):
    """获取域名报告"""
    report = make_api_request("domains", domain)
    if report:
        return report

@mcp.tool
async def get_url_report(url: str):
    """获取 URL 报告"""
    report = make_api_request("urls", url)
    if report:
        return report

if __name__ == "__main__":
    mcp.run(transport="sse", host="0.0.0.0", port=10002)
