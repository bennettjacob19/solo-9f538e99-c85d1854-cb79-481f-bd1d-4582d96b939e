# DNS 值班解析系统（serve-stale 演练）

平台值班场景：内部服务的权威 DNS 失联时，解析器继续为已确认的地址提供解析，
但记录被删除（NXDOMAIN）后绝不把旧地址交给调用方。

## 组成

| 服务 | 模块 | 端口 | 说明 |
|---|---|---|---|
| `auth` | `app.auth_server` | UDP 5354 | 本地权威端，行为可由网页实时切换 |
| `resolver` | `app.resolver` | UDP 5353 | 缓存/serve-stale UDP 解析器 |
| `web` | `app.web` | HTTP 8000 | FastAPI 操作网页 |

三者通过共享卷上的 SQLite（WAL 模式）协作：`control` 表存权威端行为，
`trial` 表存进行中的试切（绝对确认期限 + 单调递增的 `generation`），
`cache` 表存解析器缓存（**绝对时间戳**，并记录其所属 `generation`），
`query_log`/`auth_log` 表供网页展示。

## 运行

```bash
docker compose up --build
# 网页:  http://localhost:8000
# 查询:  dig @127.0.0.1 -p 5353 service.example A
```

无 Docker 的本地运行（等价三进程）：

```bash
pip install -r requirements.txt
DB_PATH=/tmp/dns/app.db AUTH_PORT=15354 python -m app.auth_server &
DB_PATH=/tmp/dns/app.db RESOLVER_PORT=15353 AUTH_PORT=15354 python -m app.resolver &
DB_PATH=/tmp/dns/app.db RESOLVER_PORT=15353 WEB_PORT=8000 python -m app.web &
```

自测（自动拉起三进程，跑全部关键交错，约 95 秒；试切场景另约 100 秒）：

```bash
python tests/selftest.py
python tests/trial_selftest.py
python tests/trial_unit.py      # 事务/代际保证的快速单元测试（无需网络）
```

## 语义（默认值，可用环境变量调整）

- 成功答复 TTL = **5 秒**（`FRESH_TTL`），缓存命中时 TTL 倒数。
- 过期后重新回源；上游超时（`UPSTREAM_TIMEOUT`=2s）时旧 A 最多沿用 **20 秒**
  （`STALE_WINDOW`），应答 TTL 为剩余可用时长；超过即 **SERVFAIL**。
- **NXDOMAIN 只作 5 秒新鲜缓存，绝不作过期备用**：过期+上游超时 → SERVFAIL。
- 解析器确认 NXDOMAIN 时**立即持久清除旧 A**：此后任何答复都不再含旧 A。
- 每次回源用**独立 socket + 随机事务 ID + 问题匹配**，超时后迟到的旧答复
  无人接收、也不会被错配给后续查询，因此无法复活旧记录。
- 缓存期限以绝对 epoch 存于 SQLite，**重启不延长旧 A 的有效期**
  （窗口继续倒数，不会重新计时）。

网页可切换权威端行为：`a`（可改 IP）/ `nxdomain` / `delay`（延迟应答，默认 3s，
大于上游超时，用于演练迟到应答）/ `timeout`（不应答，模拟权威端失联）。
网页"发起查询"经解析器发真实 DNS 查询，展示实际答复（rcode、应答、TTL）
与来源（`upstream` / `cache-fresh` / `cache-stale` / `none`，由解析器在
additional 段 TXT `_src.<域名>` 中带回），并展示双方日志。

## 试切（临时切换 A 记录）

值班员在网页第 1 节填新 IPv4 与确认期限（**10～60 秒**）开始试切，之后：

- **立即生效**：提交后新发起的真实 UDP 查询马上得到试切地址；页面显示试切
  编号、剩余时间与实际查询答复。试切期间权威端以普通 A 应答试切地址
  （不套用延迟/超时/NXDOMAIN 基模式）。
- **期限内**凭试切编号**确认**（转为常驻）或**撤销**（恢复原地址）。
- **逾期未确认**：到期那一刻自动恢复原地址；`expire` 是原子状态转换，
  任何进程读取状态时都会按**绝对期限**执行，因此重启或网页未打开也照样到期。
- **逾期确认被拒绝**（HTTP 409），撤销同理；已结束/被取代的编号不能操作。
- **普通模式切换会终止试切**：状态置为 `cancelled`，旧编号立即失效；
  旧试切的到期处理带 `status='active' AND trial_no=...` 条件，
  不可能覆盖之后的设置。
- **缓存一致性**：每次试切开始/结束都在**同一个 `BEGIN IMMEDIATE` 事务**
  里删除缓存并递增 `generation`，因此：
  - 状态改变后的新查询不会命中前一状态的缓存；
  - 回源时记录开始时的 `generation`，迟到返回的旧答复若 `generation`
    已变则**丢弃**，重新按新状态解析，绝不把失效地址写回缓存；
  - 确认/撤销与缓存失效要么一起提交、要么都不提交，写入失败保持旧状态。
- 试切状态（编号、期限、原地址、状态）持久化在 `trial` 表，重启后按原
  绝对期限继续处理。

原有 TTL（新鲜 5s）、serve-stale（20s）、NXDOMAIN、上游超时等规则在试切
结束后的普通状态下继续适用。

固定域名默认 `service.example`（`FIXED_DOMAIN` 可改）。解析器只服务该域名，
其余名称 REFUSED，非 A 查询返回 NODATA。

## 文件

```
app/common.py       配置 + SQLite 状态面（含试切事务/generation）
app/auth_server.py  可控权威端（dnslib 编解码，线程并发，试切即时覆盖）
app/resolver.py     缓存/serve-stale 解析器（generation 守卫的缓存写入）
app/web.py          FastAPI 操作网页（含试切确认/撤销）
tests/selftest.py   端到端自测（A–F 六组场景）
tests/trial_selftest.py  试切端到端自测（G–N 八组场景）
tests/trial_unit.py 事务/代际保证单元测试
Dockerfile / docker-compose.yml / requirements.txt
```
