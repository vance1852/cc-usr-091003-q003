# 陪护机器人记忆同意

陪护机器人通过同意裁决访问语音摘要、提醒与偏好记忆。领域事件同时记录发生时间、上传时间和授权主体，原始事实与删除回执互不替代。

## 资料约定

- fixtures/incident.json 保存一组可公开的事故事件，时间均带 UTC 偏移。
- fixtures/visit_incident.json 是完整叙事案例：家属探视复述、离线补传、紧急豁免、撤回与监护变更。
- src/care_consent/contracts.py 定义最小事件信封与严格校验入口。
- 未识别的业务字段保留在 attributes 中，接入方不得静默丢弃。
- event_id 标识现场事实，occurred_at 与 received_at 分别表示发生和接收时间。

## 模块划分

| 模块 | 职责 |
| --- | --- |
| `model.py` | 记忆类别（语音摘要/用药提醒/行为偏好）、场景（普通照护/家属探视/生命危险）、角色、目的与拒绝原因 |
| `policy.py` | 策略矩阵：每类记忆的收集目的、可见对象上限、保存期限硬上限、可授权场景；家属共享必须显式授权 |
| `agent.py` | 事件溯源的同意代理：按 occurred_at 重建授权时间线，裁决记录/调用，派生可追踪删除任务 |
| `reports.py` | 隐私专员调查结论与住户脱敏个人记录导出 |
| `inspect.py` | 导入案例的命令行入口（不读系统时钟，默认截止到最后一个事件） |

## 核心规则

- **三种许可不混用**：普通照护同意、家属探视共享、紧急临时豁免是独立许可。
  家属不在默认可见对象内；紧急豁免只对急救人员开放，窗口期一结束其数据即进入删除，
  不会自动转为长期同意。
- **撤回即时生效**：撤回时点之后的新调用一律拒绝；撤回时已存在的核心库记录与
  每一个下游设备副本分别生成幂等删除任务（`record@device` 为任务键，重试只增加 attempts）。
- **离线补传按事发时裁决**：以 `occurred_at` 时点有效的授权判定；
  重复上传（相同 record_id 或 event_id）折叠为一个事实，保留期不重新起算。
- **责任链不可抹除**：监护关系变更只影响此后的授权资格，旧授权记录由谁作出、
  谁撤销都保留；旧副本的删除任务不被之后的新授权取消。
- **过期与重启安全**：过期记录不可见并派生删除任务；删除回执写入墓碑后，
  重放事件流（数据库重启）不会让内容复活，已完成的任务也不会重新挂起。

## 命令行

    PYTHONPATH=src python3 -m care_consent.inspect fixtures/visit_incident.json
    PYTHONPATH=src python3 -m care_consent.inspect fixtures/visit_incident.json --record rec-voice-0001
    PYTHONPATH=src python3 -m care_consent.inspect fixtures/visit_incident.json --resident resident-014
    PYTHONPATH=src python3 -m care_consent.inspect fixtures/visit_incident.json --as-of 2026-09-18T15:00:00+08:00

## 事件类型

`resident_registered`、`guardianship_granted`/`guardianship_revoked`、
`consent_granted`/`consent_revoked`、`sharing_refused`、
`emergency_declared`/`emergency_cleared`、`memory_recorded`、
`copy_distributed`、`memory_accessed`、`memory_purged`、
`deletion_requested`/`deletion_acknowledged`。未识别事件类型保留在
`agent.unknown_events`，不静默丢弃。

## 本地校验

项目要求 Python 3.11 或更高版本，不依赖外部服务。运行下列命令可检查协议样例和源码：

    python -m unittest discover -s tests -v
    python -m compileall -q src

领域逻辑放在独立模块中，协议解析与裁决均不隐式读取系统时钟（裁决时点显式传入）。
持久化文件、临时缓存与本地配置不进入版本库。
