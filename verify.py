#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""spider-verify —— 从 nginx 访问日志里识别真假搜索引擎爬虫。

用法：
  python3 verify.py --log /var/log/nginx/access.log
  python3 verify.py --log access.log.gz --top 30 --json
  python3 verify.py --log access.log --dns          # 对 unknown 做 FCrDNS 精确校验
  python3 verify.py --ua "Mozilla/5.0 (compatible; Baiduspider/2.0)" --ip 116.179.37.2
  python3 verify.py --demo                          # 用内置样例跑一遍

日志格式：nginx 默认的 common / combined 均可，UA 取最后一个引号字段。
纯 Python 3.9+ 标准库，零第三方依赖。
项目主页：https://www.997wan.com/
"""
import argparse
import gzip
import json
import os
import re
import sys
import unicodedata
from collections import defaultdict

import bots

# IP - - [time] "METHOD path proto" status bytes "referer" "ua"
LINE_RE = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+\[[^\]]*\]\s+"(?:[^"]*)"\s+(\d{3})\s+\S+'
    r'(?:\s+"[^"]*"\s+"([^"]*)")?'
)

DEMO = [
    '116.179.37.2 - - [27/Oct/2026:10:00:01 +0800] "GET / HTTP/1.1" 200 5123 "-" "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)"',
    '116.179.37.9 - - [27/Oct/2026:10:00:05 +0800] "GET /a.html HTTP/1.1" 200 4210 "-" "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)"',
    '220.181.108.157 - - [27/Oct/2026:10:01:11 +0800] "GET /b.html HTTP/1.1" 200 3950 "-" "Mozilla/5.0 (compatible; Baiduspider/2.0)"',
    '45.9.148.37 - - [27/Oct/2026:10:02:20 +0800] "GET / HTTP/1.1" 200 5123 "-" "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)"',
    '45.9.148.37 - - [27/Oct/2026:10:02:21 +0800] "GET /wp-login.php HTTP/1.1" 404 162 "-" "Mozilla/5.0 (compatible; Baiduspider/2.0)"',
    '66.249.66.1 - - [27/Oct/2026:10:03:02 +0800] "GET / HTTP/1.1" 200 5123 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"',
    '185.220.101.4 - - [27/Oct/2026:10:04:44 +0800] "GET / HTTP/1.1" 200 5123 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"',
    '157.55.39.10 - - [27/Oct/2026:10:05:00 +0800] "GET / HTTP/1.1" 200 5123 "-" "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"',
    '20.42.65.7 - - [27/Oct/2026:10:06:12 +0800] "GET /sitemap.xml HTTP/1.1" 200 9135 "-" "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)"',
    '203.0.113.9 - - [27/Oct/2026:10:07:30 +0800] "GET / HTTP/1.1" 200 5123 "-" "curl/8.4.0"',
    '203.0.113.9 - - [27/Oct/2026:10:07:31 +0800] "GET /robots.txt HTTP/1.1" 200 412 "-" "python-requests/2.31.0"',
    '198.51.100.7 - - [27/Oct/2026:10:08:00 +0800] "GET / HTTP/1.1" 200 5123 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36"',
]

VERDICT_LABEL = {
    "real": "真",
    "fake": "假",
    "unknown": "待验",
}


def _width(s):
    """终端显示宽度：中文/全角算 2 列。"""
    return sum(2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1 for ch in str(s))


def _pad(s, width):
    s = str(s)
    return s + " " * max(0, width - _width(s))


def read_lines(path):
    if path == "-":
        return sys.stdin.read().splitlines()
    if path.endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            return f.read().splitlines()
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read().splitlines()


def parse(lines):
    """-> (total, parsed, stats, suspect)

    stats: (engine_key, verdict) -> {"hits": n, "ips": set()}
    """
    stats = defaultdict(lambda: {"hits": 0, "ips": set()})
    total = parsed = 0
    for ln in lines:
        if not ln.strip():
            continue
        total += 1
        m = LINE_RE.match(ln)
        if not m:
            continue
        ip, status, ua = m.group(1), m.group(2), (m.group(3) or "")
        key = bots.identify(ua)
        if not key:
            continue
        parsed += 1
        verdict = bots.judge(ip, key)
        cell = stats[(key, verdict)]
        cell["hits"] += 1
        if len(cell["ips"]) < 5:
            cell["ips"].add(ip)
    return total, parsed, stats


def print_table(total, parsed, stats, top):
    rows = sorted(stats.items(), key=lambda kv: -kv[1]["hits"])[:top]
    real = sum(v["hits"] for (k, verdict), v in stats.items() if verdict == "real")
    fake = sum(v["hits"] for (k, verdict), v in stats.items() if verdict == "fake")
    unknown = sum(v["hits"] for (k, verdict), v in stats.items() if verdict == "unknown")

    print("日志行数 %d | 可识别爬虫 %d 次 | 真 %d / 假 %d / 待验 %d"
          % (total, parsed, real, fake, unknown))
    print()
    print(_pad("引擎", 24) + _pad("类别", 12) + _pad("判定", 8) + _pad("次数", 8) + "样例 IP")
    print("-" * 80)
    for (key, verdict), v in rows:
        info = bots.engine_info(key)
        ips = ", ".join(sorted(v["ips"])[:2])
        print(_pad(info["name"], 24)
              + _pad(bots.CAT_NAME.get(info["cat"], info["cat"]), 12)
              + _pad(VERDICT_LABEL.get(verdict, verdict), 8)
              + _pad(v["hits"], 8)
              + ips)

    suspects = [(k, v) for (k, verdict), v in stats.items() if verdict == "fake"]
    if suspects:
        print()
        print("⚠ UA 声称是搜索引擎，IP 却不在官方段（很可能是伪造 UA 的采集器）：")
        for key, v in sorted(suspects, key=lambda kv: -kv[1]["hits"]):
            info = bots.engine_info(key)
            print("  " + _pad(info["name"], 22) + _pad("%d 次" % v["hits"], 8)
                  + ", ".join(sorted(v["ips"])))


def run_dns(stats, limit):
    """对 unknown 的 (引擎, IP) 做 FCrDNS，就地改判。"""
    todo = []
    for (key, verdict), v in stats.items():
        if verdict != "unknown":
            continue
        for ip in v["ips"]:
            todo.append((key, ip))
    todo = todo[:limit]
    if not todo:
        print("没有需要 DNS 校验的条目")
        return 0
    print("对 %d 个 IP 做 FCrDNS 校验（每个约 1-4 秒）…" % len(todo))
    upgraded = 0
    for key, ip in todo:
        r = bots.verify_host(ip, key)
        info = bots.engine_info(key)
        mark = "✓ 真" if r["ok"] else "✗ 假"
        print("  %-15s %-22s %s  %s" % (ip, info["name"], mark, r["reason"]))
        if r["ok"]:
            upgraded += 1
    return upgraded


def to_json(total, parsed, stats):
    out = []
    for (key, verdict), v in sorted(stats.items(), key=lambda kv: -kv[1]["hits"]):
        info = bots.engine_info(key)
        out.append({
            "engine": info["name"],
            "category": bots.CAT_NAME.get(info["cat"], info["cat"]),
            "verdict": verdict,
            "hits": v["hits"],
            "ips": sorted(v["ips"]),
        })
    return json.dumps({"total_lines": total, "bot_hits": parsed, "items": out},
                      ensure_ascii=False, indent=2)


def main():
    ap = argparse.ArgumentParser(
        description="识别 nginx 日志里的真假搜索引擎爬虫",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例：\n  python3 verify.py --log /var/log/nginx/access.log --top 20\n"
               "  python3 verify.py --log access.log.gz --dns\n"
               "  python3 verify.py --demo")
    ap.add_argument("--log", help="nginx 访问日志路径，支持 .gz；- 表示读 stdin")
    ap.add_argument("--top", type=int, default=20, help="展示前 N 行（默认 20）")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--dns", action="store_true", help="对 unknown 做 FCrDNS 精确校验")
    ap.add_argument("--dns-limit", type=int, default=20, help="DNS 校验最多查几个 IP（默认 20）")
    ap.add_argument("--ua", help="单条模式：只给 UA")
    ap.add_argument("--ip", help="单条模式：配合 --ua 给出源 IP")
    ap.add_argument("--demo", action="store_true", help="用内置样例数据跑一遍")
    args = ap.parse_args()

    # 单条模式
    if args.ua:
        key = bots.identify(args.ua)
        if not key:
            print("未识别为爬虫（可能是普通浏览器或未知 UA）")
            return 0
        info = bots.engine_info(key)
        print("引擎：%s\n类别：%s" % (info["name"], bots.CAT_NAME.get(info["cat"], info["cat"])))
        if args.ip:
            verdict = bots.judge(args.ip, key)
            print("IP 判定：%s（%s）" % (verdict, VERDICT_LABEL.get(verdict, verdict)))
            if verdict == "unknown":
                r = bots.verify_host(args.ip, key)
                print("FCrDNS：%s  %s" % ("通过" if r["ok"] else "未通过", r["reason"]))
        return 0

    if args.demo:
        lines = DEMO
    elif args.log:
        if args.log != "-" and not os.path.exists(args.log):
            print("找不到日志文件：%s" % args.log, file=sys.stderr)
            return 2
        lines = read_lines(args.log)
    else:
        ap.print_help()
        return 1

    total, parsed, stats = parse(lines)
    if args.json:
        print(to_json(total, parsed, stats))
        return 0

    print_table(total, parsed, stats, args.top)
    if args.dns:
        print()
        n = run_dns(stats, args.dns_limit)
        print("\nDNS 校验完成：%d 个 IP 确认为真爬虫" % n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
