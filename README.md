# 陪护机器人记忆同意

陪护机器人通过同意裁决访问语音摘要、提醒与偏好记忆。领域事件同时记录发生时间、上传时间和授权主体，原始事实与删除回执互不替代。

## 资料约定

- fixtures/incident.json 保存一组可公开的事故事件，时间均带 UTC 偏移。
- src/care_consent/contracts.py 定义最小事件信封与严格校验入口。
- 未识别的业务字段保留在 attributes 中，接入方不得静默丢弃。
- event_id 标识现场事实，occurred_at 与 received_at 分别表示发生和接收时间。

## 本地校验

项目要求 Python 3.11 或更高版本，不依赖外部服务。运行下列命令可检查协议样例和源码：

    python -m unittest discover -s tests -v
    python -m compileall -q src

领域逻辑应放在独立模块中，协议解析不得隐式读取系统时间。持久化文件、临时缓存与本地配置不进入版本库。