# XGFW

[![Quality check status](https://github.com/v2TLS/XGFW/actions/workflows/check.yaml/badge.svg)](https://github.com/v2TLS/XGFW/actions/workflows/check.yaml)

[1]: https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg

XGFW is your very own DIY Great Firewall of China (https://en.wikipedia.org/wiki/Great_Firewall), available as a flexible, easy-to-use open source program on Linux. 

## Features

- Full IP/TCP reassembly, various protocol analyzers
  - HTTP, TLS, QUIC, DNS, SSH, SOCKS4/5, WireGuard, OpenVPN, and many more to come
  - "Fully encrypted traffic" detection for Shadowsocks, VMess,
    etc. (https://gfw.report/publications/usenixsecurity23/en/)
  - Trojan (proxy protocol), XTLS Origin detection
  - Hysteria2 (proxy protocol) detection (not for production use, DO NOT WORK)
  - [WIP] Machine learning based traffic classification
- Full IPv4 and IPv6 support
- Flow-based multicore load balancing
- Connection offloading
- Powerful rule engine based on [expr](https://github.com/expr-lang/expr)
- Hot-reloadable rules (send `SIGHUP` to reload)
- Flexible analyzer & modifier framework
- Extensible IO implementation (only NFQueue for now)
- [WIP] Web UI

## Use cases

- Ad blocking
- Parental control
- Malware protection
- Abuse prevention for VPN/proxy services
- Traffic analysis (log only mode)
