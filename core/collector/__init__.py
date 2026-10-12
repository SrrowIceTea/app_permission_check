"""流量采集层：mitmproxy 反向代理、按包名时间归因、载荷捕获、/collect 接收端。

平台无关的部分在这里；**敏感载荷打标表是平台专有的**，通过 VSCAN_TAGGING_MODULE 注入。
"""
