# VirusTotal MCP Server
几个场景：
   1.经常打开不同的威胁情报网站去查询恶意ip、域名或者查询恶意文件等；
   2.难以根据得到的威胁数据进行下一步操作和处置；
   3.威胁数据可用性低。

最方便的做法是，可能我们会选择把数据粘贴给AI，让其帮助我们进一步分析。那为什么不让威胁情报数据结合AI分析之后，返回给我们友好的、可用性高的威胁情报数据和处置建议呢？

由此，便有了这一个小项目。

VirusTotal MCP Server是一个让AI结合威胁情报进行深入分析、基于 Model Context Protocol (MCP) 开发的 VirusTotal API 调用工具，为用户提供文件、IP地址、域名和URL的威胁情报查询功能，并将得到的数据喂给AI进行二次分析，提升**威胁情报分析能力**并**给予处置建议**。

最大的用途主要是，方便，高效，可用性强。另外，如果企业部署了大模型，可以嵌入相关工作流flow里（比如威胁分析、流量分析等），实现威胁的全自动化分析。

一些效果展示：

文件（哈希值）分析报告：

![image-20250609160724561](https://picgo-yxdm-hk.oss-cn-hongkong.aliyuncs.com/typora/image-20250609160724561.png)

IP分析报告：

![image-20250609161127003](https://picgo-yxdm-hk.oss-cn-hongkong.aliyuncs.com/typora/image-20250609161127003.png)

域名分析报告：

![image-20250609161159699](https://picgo-yxdm-hk.oss-cn-hongkong.aliyuncs.com/typora/image-20250609161159699.png)

友情提示：最终的结果和处置要结合实际，威胁情报是动态的，AI生成的内容是供参考的，也就是说AI和威胁情报数据源二者作用得到的结果，也仅供参考。

## 功能特性

- 🔍 **文件哈希查询** - 通过文件哈希值获取恶意软件检测报告
- 🌐 **IP地址分析** - 检查IP地址的安全威胁信息
- 🏷️ **域名检测** - 分析域名的恶意活动和信誉
- 🔗 **URL扫描** - 检测URL的安全性和威胁等级
- ⚡ **快速响应** - 基于 FastMCP 框架

## 环境要求

- Python 3.7+
- VirusTotal API 密钥

## 安装依赖

```bash
pip install uv
```

## 配置说明

1. 获取 VirusTotal API 密钥：
   - 访问 [VirusTotal](https://www.virustotal.com/) 
   - 注册账户并登录
   - 在用户设置中获取 API 密钥

2. 配置 API 密钥：
   ```python
   # 在 virusTotalServer.py 中替换以下行
   api_key = "Your VirusTotal api Key"  # 替换为您的实际API密钥
   ```

## 使用方法

### Step 1:创建和激活虚拟环境

```bash
# 初始化项目环境
uv init mcp-virusTotal
cd mcp-virusTotal
uv venv

# 激活虚拟环境
.venv\Scripts\activate

# 安装所需依赖
uv pip install mcp requests
```

### Step 2:配置API key

在脚本里配置即可。

### Step 3:第三方客户端调用（以Cherry Studio为例）

点击设置，选择MCP服务器：

![image-20250609161314000](https://picgo-yxdm-hk.oss-cn-hongkong.aliyuncs.com/typora/image-20250609161314000.png)

点击添加服务器，然后点击快速创建后，按照下图进行配置：

![image-20250609162032606](https://picgo-yxdm-hk.oss-cn-hongkong.aliyuncs.com/typora/image-20250609162032606.png)

在第四步，填入的参数为：

```
--directory
D:/workspace/mcp-project/mcp-virusTotal（你的脚本所在文件夹）
run
virusTotalServer.py
```

### Step 4:调用测试

在客户端新建会话，选择MCP工具

![image-20250609162224817](https://picgo-yxdm-hk.oss-cn-hongkong.aliyuncs.com/typora/image-20250609162224817.png)

接下来请尽情提问。

比如：

![image-20250609162309967](https://picgo-yxdm-hk.oss-cn-hongkong.aliyuncs.com/typora/image-20250609162309967.png)

![image-20250609162357439](https://picgo-yxdm-hk.oss-cn-hongkong.aliyuncs.com/typora/image-20250609162357439.png)

### 可用工具

#### 1. 文件报告查询
支持的哈希格式：MD5、SHA-1、SHA-256

#### 2. IP地址报告查询
例如：`192.168.1.1`

#### 3. 域名报告查询
例如：`example.com`

#### 4. URL报告查询
例如：`https://example.com/path`

## API 响应示例

每个查询都会返回 VirusTotal 的完整 JSON 响应，包含：

- 检测结果统计
- 各安全厂商的检测详情
- 文件/URL/域名/IP的基本信息
- 威胁情报和分类信息
- 历史检测记录

## 注意事项

⚠️ **API 限制**
- 免费账户：每分钟的频率限制
- 付费账户：根据订阅计划有不同的请求限制
- 请合理使用以避免超出配额

🔐 **安全提醒**
- 不要在代码中硬编码 API 密钥
- 建议使用环境变量或配置文件存储敏感信息
- 在生产环境中考虑使用密钥管理服务

## 许可证

本项目采用 MIT 许可证 - 详情请查看 [LICENSE](LICENSE) 文件。

## 贡献

欢迎提交 Issue 和 Pull Request 来改进本项目！

## 相关链接

- [VirusTotal API 文档](https://developers.virustotal.com/reference/overview)
- [Model Context Protocol](https://modelcontextprotocol.io/)
- [FastMCP 文档](https://github.com/jlowin/fastmcp)

## 更新日志

### v1.0.0
- 初始版本发布
- 支持文件、IP、域名、URL查询
- 基础错误处理功能
