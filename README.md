# 陪护机器人记忆同意

陪护机器人通过同意裁决访问语音摘要、提醒与偏好记忆。领域事件同时记录发生时间、上传时间和授权主体，原始事实与删除回执互不替代。

## 资料约定

- `fixtures/incident.json` 保存最小协议样例（只满足事件信封契约）。
- `fixtures/visit-incident.json` 是“探视复述”事故的完整导入案例（由
  `fixtures/build_visit_incident.py` 经同意代理真实驱动生成，44 个事件）。
- `src/care_consent/contracts.py` 定义最小事件信封与严格校验入口。
- 未识别的业务字段保留在 `attributes` 中，接入方不得静默丢弃。
- `event_id` 标识现场事实，`occurred_at` 与 `received_at` 分别表示发生和接收时间。

## 领域模块

| 模块 | 职责 |
| --- | --- |
| `domain.py` | 三类记忆（语音摘要/用药提醒/行为偏好）的目的、可见对象、保存期限上限；普通照护、家属探视、生命危险豁免三种互斥场景 |
| `ledger.py` | 事件溯源账本：授权决定、监护关系、紧急窗口、记录事实、下游副本、删除任务、访问台账均由不可变事件重放 |
| `policy.py` | 裁决引擎：记录按 **occurred_at** 裁决，调用按 **调用当时** 裁决；同意与紧急豁免是两条依据 |
| `agent.py` | 同意代理门面与 JSONL 原子持久化：授权/拒绝/撤回、记录、调用、副本分发、删除回执、暂停/恢复、到期清扫 |
| `reports.py` | 隐私专员事故报告与住户个人记录（其他自然人一律假名化），含命令行入口 |

关键合规语义：

- **场景不混用**：家属探视不能援引普通照护授权；紧急豁免不能预先“同意”，结束（或 12 小时硬上限、24 小时宽限期）后必须清除，不转为长期同意。
- **撤回即时生效**：撤回后新调用立即拒绝（记 `revoked` 越权尝试）；内容本体撕碎、只留责任元数据，所有下游副本生成带 SLA 的删除任务，回执幂等。
- **离线上传**：按发生时有效的授权裁决；落账时若已撤回或过期，立即撕碎并下发删除任务；按 `content_id` 去重，重复上传不刷新保留期。
- **责任链不可改写**：授权决定内嵌决定人、监护人与决定事件；监护关系变更不抹去旧决定。
- **重启安全**：状态全部由事件重放，过期/已删内容不会重新可见。
- 所有时间显式传入，协议解析与领域逻辑都不隐式读取系统时钟。

## 本地校验

项目要求 Python 3.11 或更高版本，不依赖外部服务：

    python -m unittest discover -s tests -v
    python -m compileall -q src

事故报告（文本或 JSON）：

    PYTHONPATH=src python -m care_consent.reports fixtures/visit-incident.json
    PYTHONPATH=src python -m care_consent.reports fixtures/visit-incident.json --record rec-visit-talk --json
    PYTHONPATH=src python -m care_consent.reports fixtures/visit-incident.json --resident resident-014

领域逻辑放在独立模块中。持久化文件（`*.jsonl`、`data/`）、临时缓存与本地配置不进入版本库。
