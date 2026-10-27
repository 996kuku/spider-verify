# spider-verify

**从 nginx 访问日志里识别真假搜索引擎爬虫：UA 指纹 + 官方 IP 段 + FCrDNS 三重校验。**

纯 Python 3 标准库，零依赖，一个文件跑起来。

> 文档与更多自建教程：**[997wan.com](https://www.997wan.com/)**　·　作者主页：[github.com/996kuku](https://github.com/996kuku)

---

## 为什么需要它

看访问日志时，`Baiduspider` 出现了几百次，但收录一条没涨——很可能你看到的是**假的**。

UA 是最容易伪造的东西，一行 `curl -A "Baiduspider"` 就能冒充。只看 UA 的统计等于自欺欺人：

| 只看 UA | 加上 IP 校验 |
|---|---|
| 「百度今天来了 320 次，很开心」 | 「其中 300 次是某个 VPS 伪装的，真百度只来了 20 次」 |

这个工具做的事就是：**先认出是谁，再判断是不是真的。**

## 判定逻辑

三层，逐层收紧：

1. **UA 正则** → 识别出「引擎 + 类别」（综合搜索 / AI 大模型 / SEO 工具 / 社交预览 / 工具监控）
2. **官方 IP 段** → 落在官方 CIDR 里的判 `real`，明显不在的判 `fake`
3. **FCrDNS 双向校验**（可选）→ 反查 PTR，再正向解析回来，确认与源 IP 一致、且域名后缀属于该厂商

```
real     命中官方 IP 段，基本可以确信
fake     UA 说是某引擎，IP 却不在官方段 —— 大概率是伪装
unknown  该引擎没有公开 IP 段（云上漂移），需要 --dns 做 FCrDNS 才能定性
```

**为什么有 unknown 而不是硬判 fake？** 因为 GPTBot、Claude、Ahrefs 这些跑在 Azure/AWS 上，IP 天天变，官方也不公布固定段。硬套一段 CIDR 会把真蜘蛛误杀，不如老实说「不确定」。

## 支持的引擎（39 个）

| 类别 | 覆盖 |
|---|---|
| 综合搜索 | 百度、Google、必应、搜狗、360、神马/UC、字节、华为、Yandex、DuckDuckGo、Apple、Amazon、Qwant |
| AI 大模型 | OpenAI GPTBot、Anthropic Claude、Perplexity、Google-Extended、Cohere、Diffbot、You.com |
| SEO 工具 | Ahrefs、Semrush、Majestic、Moz、Serpstat、Seznam、BLEXBot |
| 社交预览 | Facebook、X/Twitter、LinkedIn、Telegram、Discord、Slack、通用 Embed |
| 工具监控 | HTTP 客户端、可用性监控、RSS 订阅器、存档/学术 |

## 快速开始

```bash
git clone https://github.com/996kuku/spider-verify.git
cd spider-verify

# 用内置样例跑一遍，不碰你的真实日志
python3 verify.py --demo
```

输出：

```
日志行数 12 | 可识别爬虫 11 次 | 真 5 / 假 3 / 待验 3

引擎                    类别        判定    次数    样例 IP
--------------------------------------------------------------------------------
百度 Baiduspider        综合搜索    真      3       116.179.37.2, 116.179.37.9
百度 Baiduspider        综合搜索    假      2       45.9.148.37
HTTP 客户端             工具/监控   待验    2       203.0.113.9
Google Googlebot        综合搜索    真      1       66.249.66.1
Google Googlebot        综合搜索    假      1       185.220.101.4
必应 Bingbot            综合搜索    真      1       157.55.39.10
OpenAI GPTBot           AI 大模型   待验    1       20.42.65.7

⚠ UA 声称是搜索引擎，IP 却不在官方段（很可能是伪造 UA 的采集器）：
  百度 Baiduspider      2 次    45.9.148.37
  Google Googlebot      1 次    185.220.101.4
```

## 常用姿势

```bash
# 分析真实日志（支持 .gz，nginx 轮转的旧日志直接读）
python3 verify.py --log /var/log/nginx/access.log --top 30

# 对 unknown 的 IP 做 FCrDNS 精确校验（慢，默认最多查 20 个）
python3 verify.py --log access.log --dns

# 输出 JSON，接监控/告警
python3 verify.py --log access.log --json

# 单条查询：这个 UA + IP 是真的吗
python3 verify.py --ua "Mozilla/5.0 (compatible; Baiduspider/2.0)" --ip 116.179.37.2

# 从管道读（配合 zgrep / 别的命令）
zcat access.log.*.gz | python3 verify.py --log -
```

## 日志格式

nginx 默认的 `combined` 或 `common` 都行，UA 取最后一个引号字段。

如果日志格式被改过，确认包含这几项就够：

```nginx
log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                '$status $body_bytes_sent "$http_referer" "$http_user_agent"';
```

## 作为库使用

```python
import bots

key = bots.identify(ua)          # -> "baidu" / "google" / None
verdict = bots.judge(ip, key)    # -> "real" / "fake" / "unknown"

r = bots.verify_host(ip, key)    # FCrDNS 校验
if r["ok"]:
    print("确认是真爬虫：", r["ptr"])
```

`ENGINES` 是普通字典，想加引擎直接往里塞：

```python
ENGINES["myspider"] = dict(
    name="我的爬虫", cat="tool", color="#888",
    cidr=["203.0.113.0/24"], ptr=[".example.com"])
```

## 已知局限

- **IP 段会过期**。厂商会加新段，官方文档是唯一可信来源，建议每季度核对一次。
- **没有任何校验能 100% 确定**。伪造者如果同时控制 PTR 记录，FCrDNS 也能骗过——但成本很高，现实中极少见。
- **只解析日志，不改配置**。不会自动封禁，判定结果怎么用由你决定。

## 许可证

MIT，随便用。见 [LICENSE](LICENSE)。

---

更多自建服务、网络折腾的实操记录：**[997wan.com](https://www.997wan.com/)**
