# -*- coding: utf-8 -*-
"""搜索引擎爬虫识别 + 真伪校验（纯 Python 标准库，零依赖）。

判定分两层：
  1) UA 识别   —— 正则匹配出「引擎 + 类别」
  2) IP 归属   —— 对照该引擎官方公布的 IP 段，得出 real / fake / unknown
     对 unknown 可用 verify_host() 做 FCrDNS 精确校验（反查 PTR，再正向查回同一 IP）

设计取舍：只有厂商公布了稳定 IP 段的引擎才写 cidr；云上漂移的（GPTBot、Claude、
Ahrefs 等）刻意留空，一律判 unknown 交给 DNS 校验，宁可「不确定」也不误杀真蜘蛛。

项目主页 / 使用文档：https://www.997wan.com/
"""

import ipaddress
import re
import socket

# ---------------------------------------------------------------- 引擎定义
# key -> dict(name 中文名, cat 类别, cidr 官方IP段, ptr 合法PTR后缀)
# cat: search=综合搜索  ai=AI大模型  seo=SEO工具  social=社交预览  tool=抓取工具
ENGINES = {
    "baidu": dict(
        name="百度 Baiduspider", cat="search", color="#f85149",
        cidr=[
            "116.179.32.0/24", "116.179.37.0/24",
            "220.181.107.0/24", "220.181.108.0/24", "220.181.125.0/24",
            "123.125.66.0/24", "123.125.71.0/24",
            "180.76.15.0/24", "180.76.16.0/24", "180.76.28.0/24",
            "119.63.196.0/24", "119.63.198.0/24",
            "112.80.248.0/24", "61.135.169.0/24",
            "36.110.218.0/24", "36.110.219.0/24", "36.110.222.0/24",
            "42.236.124.0/24", "157.255.168.0/24",
        ],
        ptr=[".baidu.com", ".baidu.jp", ".baiduspider.com"]),

    "google": dict(
        name="Google Googlebot", cat="search", color="#58a6ff",
        cidr=["66.249.64.0/19", "64.233.160.0/19", "72.14.192.0/18",
              "74.125.0.0/16", "209.185.108.0/24", "203.208.60.0/24"],
        ptr=[".googlebot.com", ".google.com", ".googleusercontent.com"]),

    "bing": dict(
        name="必应 Bingbot", cat="search", color="#3fb950",
        cidr=["157.55.39.0/24", "207.46.13.0/24", "207.46.98.0/24",
              "40.77.167.0/24", "52.167.144.0/20", "13.66.139.0/24",
              "20.42.65.0/24", "40.77.188.0/24", "65.55.0.0/16"],
        ptr=[".search.msn.com", ".bing.com", ".msn.com"]),

    "sogou": dict(
        name="搜狗 Sogou", cat="search", color="#bc8cff",
        cidr=["106.120.128.0/18", "180.153.48.0/20", "220.181.125.0/24"],
        ptr=[".sogou.com"]),

    "so360": dict(
        name="360 搜索", cat="search", color="#d29922",
        cidr=["180.153.184.0/21", "101.226.102.0/24", "101.199.96.0/20",
              "42.236.10.0/24", "180.163.220.0/22"],
        ptr=[".360.cn", ".so.com", ".360safe.com"]),

    "yisou": dict(
        name="神马/UC Yisou", cat="search", color="#d29922",
        cidr=["42.120.158.0/24", "121.14.77.0/24", "112.124.12.0/22"],
        ptr=[".yisou.com", ".uc.cn", ".sm.cn"]),

    # 字节/华为等同理：云上漂移，无稳定官方段 -> 走 DNS
    "bytedance": dict(name="字节 Bytespider", cat="search", color="#f85149", cidr=[],
                      ptr=[".bytedance.com", ".toutiao.com", ".bytespider.com"]),

    "huawei": dict(name="华为 PetalBot", cat="search", color="#f85149", cidr=[],
                   ptr=[".petalsearch.com", ".huawei.com", ".aspiegel.com"]),

    "yandex": dict(
        name="Yandex", cat="search", color="#d29922",
        cidr=["5.255.192.0/18", "37.9.64.0/18", "77.88.0.0/18",
              "87.250.224.0/19", "95.108.128.0/17", "100.43.64.0/19",
              "141.8.128.0/18", "178.154.160.0/20", "180.87.48.0/20",
              "213.180.192.0/19"],
        ptr=[".yandex.ru", ".yandex.net", ".yandex.com"]),

    "duckduckgo": dict(name="DuckDuckGo", cat="search", color="#bc8cff", cidr=[],
                       ptr=[".duckduckgo.com"]),

    "apple": dict(name="Apple", cat="search", color="#c9d1d9",
                  cidr=["17.0.0.0/8"],
                  ptr=[".apple.com", ".applebot.apple.com"]),

    "amazon": dict(name="Amazonbot", cat="search", color="#d29922", cidr=[],
                   ptr=[".amazon.com", ".amazonbot.com", ".crawl.amazonbot.amazon"]),

    "qwant": dict(
        name="Qwantify", cat="search", color="#bc8cff", cidr=[], ptr=[".qwant.com"]),

    # ---------------- AI 大模型爬虫 ----------------
    # 注意：AI 类爬虫的 IP 几乎全托管在 Azure/AWS/GCP 上且频繁漂移，官方也没有公布
    # 可枚举的 IP 段。这里刻意不写 cidr —— 一律判 unknown，由 PTR 双向校验定性，
    # 否则会把真正的 GPTBot / Claude 误判成伪造。
    "openai": dict(name="OpenAI GPTBot", cat="ai", color="#3fb950", cidr=[],
                   ptr=[".openai.com", ".chatgpt.com", ".chatgpt-user.net"]),

    "anthropic": dict(name="Anthropic Claude", cat="ai", color="#3fb950", cidr=[],
                      ptr=[".anthropic.com", ".claudebot.com"]),

    "perplexity": dict(name="Perplexity", cat="ai", color="#3fb950", cidr=[],
                       ptr=[".perplexity.ai"]),

    "googleai": dict(name="Google-Extended", cat="ai", color="#58a6ff", cidr=[],
                     ptr=[".googlebot.com", ".google.com"]),

    "cohere": dict(name="Cohere", cat="ai", color="#3fb950", cidr=[], ptr=[".cohere.com"]),
    "diffbot": dict(name="Diffbot", cat="ai", color="#3fb950", cidr=[], ptr=[".diffbot.com"]),
    "you": dict(name="You.com", cat="ai", color="#3fb950", cidr=[], ptr=[".you.com"]),

    # ---------------- SEO 工具 ----------------
    # 注意：SEO 工具普遍跑在 Hetzner/AWS/OVH 等云主机上，IP 段频繁变动，
    # 这里刻意不写 cidr —— 一律判 unknown，交由 PTR 双向校验定性，避免误判成伪造。
    "ahrefs": dict(name="Ahrefs", cat="seo", color="#8b949e", cidr=[], ptr=[".ahrefs.com"]),
    "semrush": dict(name="Semrush", cat="seo", color="#8b949e", cidr=[], ptr=[".semrush.com"]),
    "majestic": dict(name="Majestic MJ12", cat="seo", color="#8b949e", cidr=[], ptr=[".majestic.com"]),
    "moz": dict(name="Moz DotBot", cat="seo", color="#8b949e", cidr=[], ptr=[".dotbot.com", ".moz.com"]),
    "serpstat": dict(name="Serpstat", cat="seo", color="#8b949e", cidr=[], ptr=[".serpstat.com", ".serpstatbot.com"]),
    "seznam": dict(name="Seznam", cat="seo", color="#8b949e", cidr=[], ptr=[".seznam.cz"]),
    "blexbot": dict(name="BLEXBot", cat="seo", color="#8b949e", cidr=[], ptr=[".webmeup.com"]),

    # ---------------- 社交 / 预览 ----------------
    "facebook": dict(name="Facebook", cat="social", color="#58a6ff", cidr=[],
                     ptr=[".facebook.com", ".fbcdn.net", ".fbsv.net"]),
    "twitter": dict(name="X/Twitter", cat="social", color="#c9d1d9", cidr=[],
                    ptr=[".twimg.com", ".twitter.com", ".x.com"]),
    "linkedin": dict(name="LinkedIn", cat="social", color="#58a6ff", cidr=[],
                     ptr=[".linkedin.com"]),
    "telegram": dict(name="Telegram", cat="social", color="#58a6ff", cidr=[],
                     ptr=[".telegram.org"]),
    "discord": dict(name="Discord", cat="social", color="#bc8cff", cidr=[],
                    ptr=[".discordapp.com", ".discord.com"]),
    "slack": dict(name="Slack", cat="social", color="#8b949e", cidr=[], ptr=[".slack.com"]),
    "preview": dict(name="预览/Embed", cat="social", color="#8b949e", cidr=[], ptr=[]),

    # ---------------- 工具 / 监控 ----------------
    "httpclient": dict(name="HTTP 客户端", cat="tool", color="#8b949e", cidr=[], ptr=[]),
    "monitor": dict(name="监控/可用性", cat="tool", color="#8b949e", cidr=[], ptr=[]),
    "feed": dict(name="RSS 订阅器", cat="tool", color="#8b949e", cidr=[], ptr=[]),
    "archive": dict(name="存档/学术", cat="tool", color="#8b949e", cidr=[], ptr=[]),

    "other": dict(name="其他爬虫", cat="other", color="#8b949e", cidr=[], ptr=[]),
}

CAT_NAME = {
    "search": "综合搜索", "ai": "AI 大模型", "seo": "SEO 工具",
    "social": "社交预览", "tool": "工具/监控", "other": "其他",
}

# UA 规则：顺序敏感，具体放前面。(正则, engine key)
UA_RULES = [
    (r"baiduspider", "baidu"),
    (r"baidu[-_]?transcoder|bdmibrowser", "baidu"),
    (r"google-extended", "googleai"),
    (r"google-cloudvertexbot|googleother|google-inspectiontool|google-safety|google-site-verification|google-read-aloud", "google"),
    (r"googlebot(-image|-video|-news|-mobile)?", "google"),
    (r"adsbot-google|apis-google|feedfetcher-google|storebot-google|mediapartners-google|google-adwords|google favicon|google web preview|google page speed|googleusercontent", "google"),
    (r"bingbot|bingpreview|msnbot|adidxbot", "bing"),
    (r"sogou[a-z ]*spider|sogou (web|inst|pic|head)", "sogou"),
    (r"360spider|haosouspider|easouspider|jikespider", "so360"),
    (r"yisou ?spider|yisouspider", "yisou"),
    (r"bytespider|bytedance spider|toutiaospider", "bytedance"),
    (r"petalbot|aspiegelbot", "huawei"),
    (r"yandex(bot|images|video|media|market|news|pagechecker|rendering|antivirus|sitelinks|spravbot)", "yandex"),
    (r"\byandex\b", "yandex"),
    (r"duckduckbot|duckduckgo-favicons-bot|duckassistantbot", "duckduckgo"),
    (r"applebot-extended", "apple"),
    (r"applebot", "apple"),
    (r"amazonbot", "amazon"),
    (r"qwantify|teoma(\s|/)|sygolbot", "qwant"),
    (r"gptbot|chatgpt-user|oai-searchbot|chatgptsearchbot", "openai"),
    (r"claudebot|claude-web|anthropic-ai", "anthropic"),
    (r"perplexitybot|perplexity-user", "perplexity"),
    (r"cohere-ai|cohere-training-data-crawler", "cohere"),
    (r"diffbot", "diffbot"),
    (r"youbot", "you"),
    (r"ahrefsbot", "ahrefs"),
    (r"semrushbot|semrushbot-ocob|splitdbot|sitebulb", "semrush"),
    (r"mj12bot", "majestic"),
    (r"dotbot|rogerbot", "moz"),
    (r"serpstatbot", "serpstat"),
    (r"seznambot", "seznam"),
    (r"blexbot", "blexbot"),
    (r"facebookexternalhit|facebookcatalog|facebot", "facebook"),
    (r"twitterbot", "twitter"),
    (r"linkedinbot", "linkedin"),
    (r"telegrambot", "telegram"),
    (r"discordbot", "discord"),
    (r"slackbot", "slack"),
    (r"embedly|quora link preview|skypeuripreview|redditbot|iframely|vkshare|whatsapp", "preview"),
    (r"^(curl|wget|python-requests|python-urllib|aiohttp|go-http-client|okhttp|axios|libwww-perl|httpx|node-fetch|undici|postmanruntime|insomnia)/", "httpclient"),
    (r"uptimerobot|pingdom|statuscake|monitor|newrelicpinger|checkly|better ?uptime|gomezagent|nagios", "monitor"),
    (r"feedbin|feedly|superfeedr|pubsubhubbub|simplepie|magpierss|universal feed parser|feedspot|newsblur|akregator", "feed"),
    (r"ccbot|archive\.org|wayback|ia_archiver|python-wayback", "archive"),
    (r"\b(bot|crawler|spider|slurp|scrapy|scraper)\b", "other"),
]

_compiled = [(re.compile(pat, re.I), key) for pat, key in UA_RULES]


# ---------------------------------------------------------------- 识别
# UA 重复度极高（几十万行日志里往往只有几千种 UA），缓存后回填可快一个数量级
_memo = {}


def identify(ua):
    """UA -> engine key，无匹配返回 None。"""
    if not ua:
        return None
    if ua in _memo:
        return _memo[ua]
    res = None
    for rx, key in _compiled:
        if rx.search(ua):
            res = key
            break
    if len(_memo) < 100000:
        _memo[ua] = res
    return res


def engine_info(key):
    return ENGINES.get(key) or ENGINES["other"]


def _nets(key):
    """惰性构建该引擎的 IP 网段列表。"""
    info = ENGINES.get(key)
    if not info:
        return []
    if "_nets" not in info:
        nets = []
        for c in info.get("cidr", []):
            try:
                nets.append(ipaddress.ip_network(c))
            except ValueError:
                pass
        info["_nets"] = nets
    return info["_nets"]


def judge(ip, key):
    """判定真伪：real / fake / unknown。

    real    命中该引擎官方 IP 段
    fake    未命中，且该引擎有公开的 IP 段定义（基本可确定是云主机伪装 UA）
    unknown 该引擎没有 IP 段定义，无法本地判定，需走 DNS 校验
    """
    if not ip or not key:
        return "unknown"
    nets = _nets(key)
    if not nets:
        return "unknown"
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return "unknown"
    for n in nets:
        try:
            if addr.version == n.version and addr in n:
                return "real"
        except TypeError:
            continue
    return "fake"


# ---------------------------------------------------------------- 精确校验
def verify_host(ip, key=None, timeout=4.0):
    """FCrDNS 双向校验：反查 PTR -> 正向解析回来 == 原 IP -> 域名后缀属于该厂商。

    返回 dict(ptr=PTR名称, fwd=正向解析结果, ok=是否通过, reason=说明)
    """
    res = dict(ptr=None, fwd=None, ok=False, reason="")
    ip = str(ip or "").strip()
    if not ip:
        res["reason"] = "无 IP"
        return res
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        try:
            res["ptr"] = socket.gethostbyaddr(ip)[0]
        except Exception as e:
            res["reason"] = "反查失败: %s" % (str(e)[:60] or type(e).__name__)
            return res
        if not key:
            res["reason"] = "未指定引擎，仅返回 PTR"
            return res
        try:
            res["fwd"] = socket.gethostbyname(res["ptr"])
        except Exception as e:
            res["reason"] = "正向解析失败: %s" % (str(e)[:60] or type(e).__name__)
            return res
        if res["fwd"] != ip:
            res["reason"] = "PTR 正向解析为 %s，与源 IP 不一致" % res["fwd"]
            return res
        ptrs = engine_info(key).get("ptr") or []
        low = res["ptr"].lower()
        if ptrs and not any(low.endswith(p.lower()) for p in ptrs):
            res["reason"] = "PTR 域名 %s 不属于该引擎官方后缀" % res["ptr"]
            return res
        res["ok"] = True
        res["reason"] = "PTR 双向校验通过"
    finally:
        socket.setdefaulttimeout(old)
    return res
