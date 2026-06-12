# 本地网络资产与 Web 安全配置风险检测报告

- 扫描目标：`127.0.0.1`
- 扫描时间：`2026-06-11 18:48:25`
- 风险等级：`中风险`
- 综合分值：`76`

## 端口扫描结果

| 端口 | 状态 | 服务 | 风险提示 |
| --- | --- | --- | --- |
| 80 | closed | HTTP | 仅暴露 HTTP 可能导致流量明文传输。 |
| 443 | closed | HTTPS | HTTPS 端口正常，但仍需检查证书与安全头。 |
| 8080 | open | HTTP-Alt | 备用 Web 端口常用于测试服务，配置疏漏概率较高。 |

## 风险明细

### 1. 疑似目录索引暴露
- 严重级别：`high`
- 风险分值：`20`
- 证据：端口 8080 页面内容包含 'Index of /'
- 建议：关闭目录浏览功能，避免静态资源、日志或备份文件被遍历获取。

### 2. 开放端口 8080 暴露风险
- 严重级别：`medium`
- 风险分值：`10`
- 证据：8080/HTTP-Alt 处于开放状态。备用 Web 端口常用于测试服务，配置疏漏概率较高。
- 建议：确认端口是否必须对外开放；若非必要，应关闭或限制访问来源。

### 3. 缺少安全响应头 Strict-Transport-Security
- 严重级别：`medium`
- 风险分值：`10`
- 证据：端口 8080 响应中未发现 Strict-Transport-Security
- 建议：在 Web 服务或反向代理中补充 Strict-Transport-Security 配置。

### 4. 缺少安全响应头 Content-Security-Policy
- 严重级别：`medium`
- 风险分值：`10`
- 证据：端口 8080 响应中未发现 Content-Security-Policy
- 建议：在 Web 服务或反向代理中补充 Content-Security-Policy 配置。

### 5. Server 版本信息暴露
- 严重级别：`medium`
- 风险分值：`8`
- 证据：端口 8080 返回 Server 头: Apache/2.4.49
- 建议：隐藏精确版本号，仅保留必要产品标识，降低被针对性攻击概率。

### 6. 缺少安全响应头 X-Frame-Options
- 严重级别：`medium`
- 风险分值：`8`
- 证据：端口 8080 响应中未发现 X-Frame-Options
- 建议：在 Web 服务或反向代理中补充 X-Frame-Options 配置。

### 7. 缺少安全响应头 X-Content-Type-Options
- 严重级别：`low`
- 风险分值：`6`
- 证据：端口 8080 响应中未发现 X-Content-Type-Options
- 建议：在 Web 服务或反向代理中补充 X-Content-Type-Options 配置。

### 8. 缺少安全响应头 Referrer-Policy
- 严重级别：`low`
- 风险分值：`4`
- 证据：端口 8080 响应中未发现 Referrer-Policy
- 建议：在 Web 服务或反向代理中补充 Referrer-Policy 配置。

## 统计摘要

- 高风险：1 项
- 中风险：5 项
- 低风险：2 项