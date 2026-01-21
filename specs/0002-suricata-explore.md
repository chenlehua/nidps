# 基于 Suricata 的入侵检测系统方案探索

## 1. 项目概述

### 1.1 目标

构建一个完整的入侵检测系统（IDS），具备以下核心能力：
- 基于 Suricata 引擎进行网络流量检测
- 集成 Emerging Threats Open 规则集
- 提供 Web 管理界面
- 支持规则自动/手动更新与版本管理
- 支持攻击流量生成与规则验证测试

### 1.2 可行性结论

| 需求 | 可行性 | 技术方案 |
|------|--------|----------|
| 前端告警展示 | ✅ 完全可行 | React/Vue + EVE JSON 解析 |
| 规则管理 | ✅ 完全可行 | suricata-update + 自定义规则存储 |
| 定时规则更新 | ✅ 完全可行 | Cron/APScheduler + suricata-update |
| 规则版本管理 | ✅ 完全可行 | Git 或数据库版本控制 |
| 攻击流量生成 | ✅ 可行 | Scapy + tcpreplay + 规则解析 |
| LLM 辅助生成 | ⚠️ 部分可行 | 需谨慎设计，适合辅助而非完全自动 |
| 告警-规则关联 | ✅ 完全可行 | EVE JSON 中的 signature_id 字段 |

---

## 2. 系统架构设计

### 2.1 整体架构

```mermaid
graph TB
    subgraph "用户层 User Layer"
        WebUI[Web 管理界面<br/>React/Vue]
    end

    subgraph "应用层 Application Layer"
        API[REST API 服务<br/>FastAPI/Django]
        RuleEngine[规则管理引擎]
        AlertEngine[告警处理引擎]
        TestEngine[攻击测试引擎]
    end

    subgraph "核心层 Core Layer"
        Suricata[Suricata IDS 引擎]
        RuleDB[(规则数据库<br/>PostgreSQL)]
        AlertDB[(告警数据库<br/>Elasticsearch)]
        MQ[消息队列<br/>Redis/Kafka]
    end

    subgraph "数据层 Data Layer"
        ETOpen[ET Open 规则源]
        Network[网络流量<br/>镜像/TAP]
        TestNIC[测试网卡<br/>虚拟接口]
    end

    WebUI <--> API
    API <--> RuleEngine
    API <--> AlertEngine
    API <--> TestEngine

    RuleEngine <--> RuleDB
    RuleEngine --> Suricata
    RuleEngine <--> ETOpen

    Suricata --> MQ
    MQ --> AlertEngine
    AlertEngine --> AlertDB

    TestEngine --> TestNIC
    TestNIC --> Suricata
    Network --> Suricata

    AlertDB <--> API
    RuleDB <--> API
```

### 2.2 组件关系图

```mermaid
graph LR
    subgraph "前端组件"
        Dashboard[仪表盘]
        AlertView[告警视图]
        RuleManager[规则管理]
        TestConsole[测试控制台]
    end

    subgraph "后端服务"
        APIGateway[API 网关]
        AuthService[认证服务]
        RuleService[规则服务]
        AlertService[告警服务]
        TestService[测试服务]
        SchedulerService[调度服务]
    end

    subgraph "基础设施"
        SuricataCluster[Suricata 集群]
        ES[Elasticsearch]
        PG[PostgreSQL]
        Redis[Redis]
    end

    Dashboard --> APIGateway
    AlertView --> APIGateway
    RuleManager --> APIGateway
    TestConsole --> APIGateway

    APIGateway --> AuthService
    APIGateway --> RuleService
    APIGateway --> AlertService
    APIGateway --> TestService

    RuleService --> PG
    RuleService --> SuricataCluster
    AlertService --> ES
    TestService --> SuricataCluster
    SchedulerService --> RuleService
    SchedulerService --> Redis
```

---

## 3. 核心模块设计

### 3.1 告警日志模块

#### 3.1.1 EVE JSON 告警格式

Suricata 的 EVE JSON 输出是告警数据的核心来源：

```json
{
  "timestamp": "2024-01-15T10:30:45.123456+0800",
  "flow_id": 1234567890123456,
  "in_iface": "eth0",
  "event_type": "alert",
  "src_ip": "192.168.1.100",
  "src_port": 54321,
  "dest_ip": "10.0.0.50",
  "dest_port": 80,
  "proto": "TCP",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 2024897,
    "rev": 3,
    "signature": "ET MALWARE Suspicious User-Agent (wget)",
    "category": "A Network Trojan was Detected",
    "severity": 1,
    "metadata": {
      "attack_target": ["Client_Endpoint"],
      "created_at": ["2023_01_15"],
      "deployment": ["Perimeter"],
      "signature_severity": ["Major"],
      "tag": ["Wget"],
      "updated_at": ["2024_01_10"]
    }
    },
  "http": {
    "hostname": "malware.example.com",
    "url": "/payload.exe",
    "http_user_agent": "Wget/1.21",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "status": 200,
    "length": 102400
  },
  "app_proto": "http",
  "flow": {
    "pkts_toserver": 5,
    "pkts_toclient": 10,
    "bytes_toserver": 512,
    "bytes_toclient": 102912,
    "start": "2024-01-15T10:30:44.000000+0800"
  }
}
```

#### 3.1.2 告警处理流程

```mermaid
sequenceDiagram
    participant Net as 网络流量
    participant Suri as Suricata
    participant EVE as EVE JSON
    participant Parser as 日志解析器
    participant MQ as 消息队列
    participant Proc as 告警处理器
    participant ES as Elasticsearch
    participant WS as WebSocket
    participant UI as 前端界面

    Net->>Suri: 网络数据包
    Suri->>Suri: 规则匹配检测
    Suri->>EVE: 写入告警日志

    EVE->>Parser: 实时读取 (tail -f)
    Parser->>Parser: JSON 解析
    Parser->>MQ: 发布告警消息

    MQ->>Proc: 消费告警
    Proc->>Proc: 数据丰富化
    Note over Proc: 添加规则详情<br/>地理位置信息<br/>威胁情报关联
    Proc->>ES: 存储告警
    Proc->>WS: 推送实时告警

    WS->>UI: 实时更新
    UI->>ES: 查询历史告警
    ES->>UI: 返回告警列表
```

#### 3.1.3 告警-规则关联机制

```mermaid
erDiagram
    ALERT ||--o{ RULE : "references"
    ALERT {
        string id PK
        timestamp timestamp
        int signature_id FK
        string src_ip
        string dest_ip
        int src_port
        int dest_port
        string protocol
        string category
        int severity
        json metadata
        json flow_info
        json http_info
    }

    RULE {
        int sid PK
        string msg
        string classtype
        int rev
        string content
        string raw_rule
        boolean enabled
        string source
        timestamp updated_at
    }

    RULE_VERSION {
        int id PK
        int sid FK
        int version
        string raw_rule
        timestamp created_at
        string change_type
    }

    RULE ||--o{ RULE_VERSION : "has versions"
```

### 3.2 规则管理模块

#### 3.2.1 规则更新流程

```mermaid
flowchart TD
    Start([开始更新]) --> CheckSchedule{定时触发<br/>或手动触发?}

    CheckSchedule -->|定时| Cron[Cron 调度器]
    CheckSchedule -->|手动| API[API 请求]

    Cron --> FetchRules
    API --> FetchRules

    FetchRules[调用 suricata-update<br/>获取 ET Open 规则]
    FetchRules --> Download[下载规则包<br/>rules.emergingthreats.net]

    Download --> ValidateMD5{校验 MD5}
    ValidateMD5 -->|失败| RetryDownload[重试下载]
    RetryDownload --> Download
    ValidateMD5 -->|成功| Extract[解压规则文件]

    Extract --> ParseRules[解析规则文件]
    ParseRules --> DiffRules[对比现有规则]

    DiffRules --> HasChanges{有变更?}
    HasChanges -->|否| End([结束])
    HasChanges -->|是| CreateVersion[创建版本快照]

    CreateVersion --> UpdateDB[更新规则数据库]
    UpdateDB --> MergeRules[合并为 suricata.rules]
    MergeRules --> ReloadSuricata[重载 Suricata 规则]

    ReloadSuricata --> VerifyReload{重载成功?}
    VerifyReload -->|成功| NotifySuccess[通知更新成功]
    VerifyReload -->|失败| Rollback[回滚到上一版本]
    Rollback --> NotifyFail[通知更新失败]

    NotifySuccess --> End
    NotifyFail --> End
```

#### 3.2.2 规则版本管理架构

```mermaid
graph TB
    subgraph "规则版本控制"
        Current[当前版本<br/>v2024.01.15.001]
        Prev1[上一版本<br/>v2024.01.14.002]
        Prev2[历史版本<br/>v2024.01.13.001]

        Current --> Prev1
        Prev1 --> Prev2
    end

    subgraph "版本操作"
        Diff[版本对比]
        Rollback[版本回滚]
        Export[版本导出]
    end

    subgraph "存储方案"
        GitRepo[(Git 仓库<br/>规则文件版本)]
        PGDB[(PostgreSQL<br/>规则元数据)]
        FileStore[(文件存储<br/>规则包归档)]
    end

    Current --> Diff
    Current --> Rollback
    Current --> Export

    Diff --> GitRepo
    Rollback --> GitRepo
    Export --> FileStore

    Current --> PGDB
    Prev1 --> PGDB
    Prev2 --> PGDB
```

#### 3.2.3 suricata-update 集成

```bash
# 更新命令示例
suricata-update \
    --suricata-conf /etc/suricata/suricata.yaml \
    --output-dir /var/lib/suricata/rules \
    --url https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz \
    --reload-command "suricatasc -c reload-rules"
```

**配置文件 `/etc/suricata/update.yaml`**:
```yaml
sources:
  - et/open

# 启用/禁用特定规则
enable-conf: /etc/suricata/enable.conf
disable-conf: /etc/suricata/disable.conf

# 输出目录
output-directory: /var/lib/suricata/rules

# 合并后的规则文件
merged-rule-file: suricata.rules
```

### 3.3 攻击测试模块

#### 3.3.1 测试流程架构

```mermaid
flowchart LR
    subgraph "输入"
        Rule[选定规则]
        Config[测试配置]
    end

    subgraph "流量生成"
        Parser[规则解析器]
        Generator[流量生成器]
        LLM[LLM 辅助<br/>可选]
    end

    subgraph "测试执行"
        PCAP[PCAP 文件]
        Replay[tcpreplay]
        Scapy[Scapy 实时]
    end

    subgraph "验证"
        Monitor[告警监控]
        Compare[结果对比]
        Report[测试报告]
    end

    Rule --> Parser
    Config --> Parser
    Parser --> Generator
    LLM -.->|辅助生成| Generator

    Generator --> PCAP
    Generator --> Scapy

    PCAP --> Replay
    Replay --> TestNIC[测试网卡]
    Scapy --> TestNIC

    TestNIC --> Suricata[Suricata]
    Suricata --> Monitor
    Monitor --> Compare
    Compare --> Report
```

#### 3.3.2 规则解析与流量生成

```mermaid
sequenceDiagram
    participant User as 用户
    participant API as API 服务
    participant Parser as 规则解析器
    participant LLM as LLM 服务
    participant Gen as 流量生成器
    participant Exec as 测试执行器
    participant Suri as Suricata

    User->>API: 选择规则进行测试
    API->>Parser: 解析规则内容

    Parser->>Parser: 提取关键字段
    Note over Parser: content, pcre,<br/>flow, dsize,<br/>http.uri 等

    alt 简单规则 (明确 content)
        Parser->>Gen: 直接生成流量
    else 复杂规则 (pcre/逻辑复杂)
        Parser->>LLM: 请求辅助分析
        LLM->>LLM: 分析正则模式
        LLM->>Gen: 返回建议 payload
    end

    Gen->>Gen: 构造数据包
    Gen->>Exec: 发送测试流量

    Exec->>Suri: 注入流量到测试网卡
    Suri->>Suri: 规则匹配
    Suri->>API: 产生告警

    API->>User: 返回测试结果
    Note over User: 显示是否触发<br/>匹配详情
```

#### 3.3.3 流量生成策略

```mermaid
graph TB
    subgraph "规则类型识别"
        RuleInput[输入规则] --> Analyze[分析规则类型]
        Analyze --> HTTP{HTTP 规则?}
        Analyze --> DNS{DNS 规则?}
        Analyze --> TCP{TCP 规则?}
        Analyze --> ICMP{ICMP 规则?}
    end

    subgraph "生成策略"
        HTTP -->|是| HTTPGen[HTTP 流量生成器]
        DNS -->|是| DNSGen[DNS 流量生成器]
        TCP -->|是| TCPGen[TCP 流量生成器]
        ICMP -->|是| ICMPGen[ICMP 流量生成器]

        HTTPGen --> ScapyHTTP[Scapy HTTP 构造]
        DNSGen --> ScapyDNS[Scapy DNS 构造]
        TCPGen --> ScapyTCP[Scapy TCP 构造]
        ICMPGen --> ScapyICMP[Scapy ICMP 构造]
    end

    subgraph "执行方式"
        ScapyHTTP --> Method1[方式1: Scapy 直接发送]
        ScapyDNS --> Method1
        ScapyTCP --> Method1
        ScapyICMP --> Method1

        ScapyHTTP --> Method2[方式2: 生成 PCAP]
        ScapyDNS --> Method2
        ScapyTCP --> Method2
        ScapyICMP --> Method2

        Method2 --> TCPReplay[tcpreplay 重放]
    end
```

#### 3.3.4 Scapy 流量生成示例

```python
# 示例：基于规则生成攻击流量

from scapy.all import *
import re

class RuleBasedTrafficGenerator:
    """基于 Suricata 规则生成测试流量"""

    def parse_rule(self, rule_text: str) -> dict:
        """解析 Suricata 规则"""
        parsed = {
            'proto': None,
            'src_ip': None,
            'src_port': None,
            'dst_ip': None,
            'dst_port': None,
            'content': [],
            'http_uri': None,
            'http_method': None,
            'http_header': None,
        }

        # 解析规则头部
        header_match = re.match(
            r'alert\s+(\w+)\s+(\S+)\s+(\S+)\s+->\s+(\S+)\s+(\S+)',
            rule_text
        )
        if header_match:
            parsed['proto'] = header_match.group(1)
            parsed['src_ip'] = header_match.group(2)
            parsed['src_port'] = header_match.group(3)
            parsed['dst_ip'] = header_match.group(4)
            parsed['dst_port'] = header_match.group(5)

        # 解析 content 关键字
        content_matches = re.findall(r'content:"([^"]+)"', rule_text)
        parsed['content'] = content_matches

        # 解析 HTTP 特定字段
        if 'http.uri' in rule_text or 'http_uri' in rule_text:
            uri_match = re.search(r'content:"([^"]+)".*?http\.uri', rule_text)
            if uri_match:
                parsed['http_uri'] = uri_match.group(1)

        return parsed

    def generate_http_traffic(self, parsed_rule: dict,
                               target_ip: str = "10.0.0.1",
                               target_port: int = 80) -> Packet:
        """生成 HTTP 攻击流量"""

        # 构建 payload
        uri = parsed_rule.get('http_uri', '/')
        content_parts = parsed_rule.get('content', [])

        # 构造 HTTP 请求
        http_request = f"GET {uri} HTTP/1.1\r\n"
        http_request += f"Host: {target_ip}\r\n"

        # 添加 content 匹配内容
        for content in content_parts:
            if content not in http_request:
                http_request += f"X-Custom: {content}\r\n"

        http_request += "\r\n"

        # 构建数据包
        pkt = IP(dst=target_ip) / \
              TCP(dport=target_port, flags='PA') / \
              Raw(load=http_request.encode())

        return pkt

    def generate_and_send(self, rule_text: str,
                          interface: str = "eth0"):
        """解析规则并发送测试流量"""
        parsed = self.parse_rule(rule_text)

        if parsed['proto'].lower() == 'http' or \
           'http' in rule_text.lower():
            pkt = self.generate_http_traffic(parsed)
            sendp(Ether()/pkt, iface=interface)
            return True

        return False

    def save_to_pcap(self, packets: list, filename: str):
        """保存数据包到 PCAP 文件"""
        wrpcap(filename, packets)


# 使用示例
if __name__ == "__main__":
    generator = RuleBasedTrafficGenerator()

    # 示例规则
    rule = '''alert http $HOME_NET any -> $EXTERNAL_NET any (
        msg:"ET MALWARE Suspicious User-Agent";
        content:"wget";
        http.user_agent;
        sid:2024001;
    )'''

    # 生成并发送流量
    generator.generate_and_send(rule, interface="test0")
```

### 3.4 LLM 辅助模块

#### 3.4.1 LLM 集成架构

```mermaid
graph TB
    subgraph "LLM 服务层"
        LLMRouter[LLM 路由器]
        LocalLLM[本地 LLM<br/>Ollama/vLLM]
        CloudLLM[云端 LLM<br/>OpenAI/Claude]
    end

    subgraph "提示工程"
        RulePrompt[规则分析提示]
        PayloadPrompt[Payload 生成提示]
        ValidationPrompt[验证分析提示]
    end

    subgraph "安全控制"
        Sandbox[沙箱环境]
        Validator[输出验证器]
        RateLimit[速率限制]
    end

    RulePrompt --> LLMRouter
    PayloadPrompt --> LLMRouter
    ValidationPrompt --> LLMRouter

    LLMRouter --> LocalLLM
    LLMRouter --> CloudLLM

    LocalLLM --> Sandbox
    CloudLLM --> Sandbox
    Sandbox --> Validator
    Validator --> RateLimit
```

#### 3.4.2 LLM 辅助场景

| 场景 | LLM 作用 | 安全考量 |
|------|----------|----------|
| 复杂 PCRE 解析 | 分析正则表达式，生成匹配样本 | 输出需验证 |
| Payload 建议 | 根据规则描述生成测试 payload | 仅限测试环境 |
| 规则解释 | 将规则翻译为人类可读描述 | 低风险 |
| 误报分析 | 分析告警是否为误报 | 辅助决策 |

#### 3.4.3 LLM Prompt 示例

```python
RULE_ANALYSIS_PROMPT = """
你是一个网络安全专家，专门分析 Suricata IDS 规则。

请分析以下规则并提供：
1. 规则的检测目标（什么类型的攻击/行为）
2. 关键匹配条件解释
3. 建议的测试流量特征

规则内容：
{rule_content}

请以 JSON 格式返回：
{{
    "target_description": "检测目标描述",
    "match_conditions": [
        {{"field": "字段名", "value": "匹配值", "explanation": "解释"}}
    ],
    "test_traffic_suggestion": {{
        "protocol": "协议",
        "method": "方法（如适用）",
        "payload_hints": ["关键内容1", "关键内容2"]
    }}
}}
"""

PAYLOAD_GENERATION_PROMPT = """
基于以下 Suricata 规则分析，生成一个能触发该规则的测试 HTTP 请求。

规则分析：
{rule_analysis}

要求：
1. 生成的请求必须是无害的测试请求
2. 包含触发规则所需的所有特征
3. 使用标准 HTTP 格式

返回格式：
```http
GET /path HTTP/1.1
Host: example.com
...
```
"""
```

---

## 4. 前端设计

### 4.1 页面结构

```mermaid
graph TB
    subgraph "导航结构"
        Home[首页仪表盘]
        Alerts[告警中心]
        Rules[规则管理]
        Test[测试工具]
        Settings[系统设置]
    end

    subgraph "告警中心"
        AlertList[告警列表]
        AlertDetail[告警详情]
        AlertStats[告警统计]
        AlertFilter[高级筛选]
    end

    subgraph "规则管理"
        RuleList[规则列表]
        RuleDetail[规则详情]
        RuleVersion[版本历史]
        RuleUpdate[规则更新]
        RuleCustom[自定义规则]
    end

    subgraph "测试工具"
        TestSelect[选择规则]
        TestConfig[配置参数]
        TestExec[执行测试]
        TestResult[查看结果]
    end

    Home --> Alerts
    Home --> Rules
    Home --> Test
    Home --> Settings

    Alerts --> AlertList
    AlertList --> AlertDetail
    Alerts --> AlertStats
    Alerts --> AlertFilter

    Rules --> RuleList
    RuleList --> RuleDetail
    Rules --> RuleVersion
    Rules --> RuleUpdate
    Rules --> RuleCustom

    Test --> TestSelect
    TestSelect --> TestConfig
    TestConfig --> TestExec
    TestExec --> TestResult
```

### 4.2 告警视图设计

```mermaid
graph LR
    subgraph "告警列表页"
        Filter[筛选器<br/>时间/严重级/类型]
        Table[告警表格<br/>时间/源IP/目的IP/规则/严重级]
        Pagination[分页控件]
        Export[导出功能]
    end

    subgraph "告警详情页"
        BasicInfo[基本信息<br/>时间/IP/端口/协议]
        RuleInfo[关联规则<br/>SID/描述/分类]
        FlowInfo[流量信息<br/>包数/字节数/持续时间]
        PayloadView[Payload 查看<br/>十六进制/ASCII]
        Timeline[时间线<br/>同流程其他事件]
    end

    Table -->|点击| BasicInfo
    BasicInfo --> RuleInfo
    BasicInfo --> FlowInfo
    BasicInfo --> PayloadView
    BasicInfo --> Timeline
```

### 4.3 前端技术栈

| 层级 | 技术选型 | 说明 |
|------|----------|------|
| 框架 | React 18 / Vue 3 | 现代前端框架 |
| UI 组件 | Ant Design / Element Plus | 企业级组件库 |
| 状态管理 | Zustand / Pinia | 轻量状态管理 |
| 图表 | ECharts / Apache Superset | 数据可视化 |
| 实时通信 | WebSocket | 实时告警推送 |
| HTTP 客户端 | Axios | API 调用 |

---

## 5. 后端设计

### 5.1 API 设计

```mermaid
graph TB
    subgraph "API 路由结构"
        direction TB
        Root["/api/v1"]

        Root --> AuthAPI["/auth"]
        Root --> AlertAPI["/alerts"]
        Root --> RuleAPI["/rules"]
        Root --> TestAPI["/tests"]
        Root --> SystemAPI["/system"]

        AuthAPI --> Login["POST /login"]
        AuthAPI --> Logout["POST /logout"]
        AuthAPI --> Refresh["POST /refresh"]

        AlertAPI --> ListAlerts["GET /"]
        AlertAPI --> GetAlert["GET /{id}"]
        AlertAPI --> AlertStats["GET /stats"]
        AlertAPI --> ExportAlerts["GET /export"]

        RuleAPI --> ListRules["GET /"]
        RuleAPI --> GetRule["GET /{sid}"]
        RuleAPI --> UpdateRules["POST /update"]
        RuleAPI --> EnableRule["PUT /{sid}/enable"]
        RuleAPI --> DisableRule["PUT /{sid}/disable"]
        RuleAPI --> RuleVersions["GET /{sid}/versions"]
        RuleAPI --> Rollback["POST /rollback"]

        TestAPI --> CreateTest["POST /"]
        TestAPI --> GetTestResult["GET /{id}"]
        TestAPI --> ListTests["GET /"]
    end
```

### 5.2 核心 API 接口定义

```yaml
# OpenAPI 3.0 规范片段

paths:
  /api/v1/alerts:
    get:
      summary: 获取告警列表
      parameters:
        - name: start_time
          in: query
          schema:
            type: string
            format: date-time
        - name: end_time
          in: query
          schema:
            type: string
            format: date-time
        - name: severity
          in: query
          schema:
            type: integer
            enum: [1, 2, 3]
        - name: signature_id
          in: query
          schema:
            type: integer
        - name: src_ip
          in: query
          schema:
            type: string
        - name: page
          in: query
          schema:
            type: integer
            default: 1
        - name: page_size
          in: query
          schema:
            type: integer
            default: 20
      responses:
        '200':
          description: 成功
          content:
            application/json:
              schema:
                type: object
                properties:
                  total:
                    type: integer
                  items:
                    type: array
                    items:
                      $ref: '#/components/schemas/Alert'

  /api/v1/rules/{sid}:
    get:
      summary: 获取规则详情
      parameters:
        - name: sid
          in: path
          required: true
          schema:
            type: integer
      responses:
        '200':
          description: 成功
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Rule'

  /api/v1/rules/update:
    post:
      summary: 触发规则更新
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                source:
                  type: string
                  enum: [et-open, custom]
                force:
                  type: boolean
                  default: false
      responses:
        '202':
          description: 更新任务已接受

  /api/v1/tests:
    post:
      summary: 创建攻击测试
      requestBody:
        content:
          application/json:
            schema:
              type: object
              required:
                - rule_sid
              properties:
                rule_sid:
                  type: integer
                target_ip:
                  type: string
                  default: "127.0.0.1"
                target_port:
                  type: integer
                  default: 80
                use_llm:
                  type: boolean
                  default: false
      responses:
        '201':
          description: 测试已创建
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/TestResult'

components:
  schemas:
    Alert:
      type: object
      properties:
        id:
          type: string
        timestamp:
          type: string
          format: date-time
        signature_id:
          type: integer
        signature:
          type: string
        src_ip:
          type: string
        dest_ip:
          type: string
        severity:
          type: integer
        category:
          type: string

    Rule:
      type: object
      properties:
        sid:
          type: integer
        msg:
          type: string
        classtype:
          type: string
        enabled:
          type: boolean
        raw_rule:
          type: string
        version:
          type: integer
        updated_at:
          type: string
          format: date-time

    TestResult:
      type: object
      properties:
        id:
          type: string
        rule_sid:
          type: integer
        status:
          type: string
          enum: [pending, running, success, failed]
        triggered:
          type: boolean
        alert_id:
          type: string
        created_at:
          type: string
          format: date-time
```

### 5.3 后端技术栈

| 组件 | 技术选型 | 说明 |
|------|----------|------|
| Web 框架 | FastAPI | 高性能异步框架 |
| ORM | SQLAlchemy 2.0 | 数据库 ORM |
| 任务队列 | Celery | 异步任务处理 |
| 缓存 | Redis | 缓存和消息队列 |
| 日志解析 | Filebeat + 自定义 Parser | EVE JSON 解析 |
| 搜索引擎 | Elasticsearch 8.x | 告警存储和搜索 |
| 数据库 | PostgreSQL 15 | 规则和配置存储 |

---

## 6. 部署架构

### 6.1 Docker Compose 部署

```mermaid
graph TB
    subgraph "Docker 网络"
        subgraph "前端容器"
            Nginx[Nginx<br/>:80/:443]
            Frontend[React App]
        end

        subgraph "后端容器"
            API[FastAPI<br/>:8000]
            Worker[Celery Worker]
            Beat[Celery Beat<br/>调度器]
        end

        subgraph "核心服务容器"
            Suricata[Suricata<br/>IDS 引擎]
            LogParser[日志解析器]
        end

        subgraph "数据容器"
            ES[Elasticsearch<br/>:9200]
            PG[PostgreSQL<br/>:5432]
            Redis[Redis<br/>:6379]
        end
    end

    subgraph "外部"
        User[用户]
        Network[网络流量]
        ETOpen[ET Open<br/>规则源]
    end

    User --> Nginx
    Nginx --> Frontend
    Nginx --> API

    Network --> Suricata
    Suricata --> LogParser
    LogParser --> Redis

    API --> PG
    API --> ES
    API --> Redis

    Worker --> PG
    Worker --> ES
    Worker --> Suricata

    Beat --> Redis
    Worker --> ETOpen
```

### 6.2 网络配置

```mermaid
graph LR
    subgraph "生产网络"
        Mirror[镜像端口/TAP]
        ProdTraffic[生产流量]
    end

    subgraph "检测网络"
        SuriNIC[Suricata 监听网卡<br/>eth0 - 混杂模式]
    end

    subgraph "测试网络"
        TestNIC[测试网卡<br/>veth0 - 虚拟接口]
        TestGen[流量生成器]
    end

    subgraph "管理网络"
        MgmtNIC[管理网卡<br/>eth1]
        WebUI[Web 界面]
        API[API 服务]
    end

    ProdTraffic --> Mirror
    Mirror --> SuriNIC

    TestGen --> TestNIC
    TestNIC --> SuriNIC

    WebUI --> MgmtNIC
    API --> MgmtNIC
    MgmtNIC --> SuriNIC
```

### 6.3 Docker Compose 配置示例

```yaml
version: '3.8'

services:
  # Suricata IDS
  suricata:
    image: jasonish/suricata:latest
    container_name: suricata
    network_mode: host
    cap_add:
      - NET_ADMIN
      - SYS_NICE
    volumes:
      - ./suricata/etc:/etc/suricata
      - ./suricata/rules:/var/lib/suricata/rules
      - ./suricata/logs:/var/log/suricata
      - /var/run/suricata:/var/run/suricata
    command: -i eth0 --init-errors-fatal
    restart: unless-stopped

  # 日志解析器
  log-parser:
    build: ./services/log-parser
    container_name: log-parser
    volumes:
      - ./suricata/logs:/var/log/suricata:ro
    environment:
      - REDIS_URL=redis://redis:6379
      - ES_URL=http://elasticsearch:9200
    depends_on:
      - redis
      - elasticsearch
    restart: unless-stopped

  # API 服务
  api:
    build: ./services/api
    container_name: api
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://user:pass@postgres:5432/idps
      - REDIS_URL=redis://redis:6379
      - ES_URL=http://elasticsearch:9200
      - SURICATA_SOCKET=/var/run/suricata/suricata-command.socket
    volumes:
      - ./suricata/rules:/var/lib/suricata/rules
      - /var/run/suricata:/var/run/suricata
    depends_on:
      - postgres
      - redis
      - elasticsearch
    restart: unless-stopped

  # Celery Worker
  celery-worker:
    build: ./services/api
    container_name: celery-worker
    command: celery -A app.celery worker -l info
    environment:
      - DATABASE_URL=postgresql://user:pass@postgres:5432/idps
      - REDIS_URL=redis://redis:6379
    volumes:
      - ./suricata/rules:/var/lib/suricata/rules
    depends_on:
      - redis
      - postgres
    restart: unless-stopped

  # Celery Beat (调度器)
  celery-beat:
    build: ./services/api
    container_name: celery-beat
    command: celery -A app.celery beat -l info
    environment:
      - REDIS_URL=redis://redis:6379
    depends_on:
      - redis
    restart: unless-stopped

  # 前端
  frontend:
    build: ./services/frontend
    container_name: frontend
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./nginx/ssl:/etc/nginx/ssl
    depends_on:
      - api
    restart: unless-stopped

  # PostgreSQL
  postgres:
    image: postgres:15
    container_name: postgres
    environment:
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=pass
      - POSTGRES_DB=idps
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped

  # Redis
  redis:
    image: redis:7-alpine
    container_name: redis
    volumes:
      - redis_data:/data
    restart: unless-stopped

  # Elasticsearch
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
    container_name: elasticsearch
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - "ES_JAVA_OPTS=-Xms2g -Xmx2g"
    volumes:
      - es_data:/usr/share/elasticsearch/data
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
  es_data:
```

---

## 7. 数据流设计

### 7.1 告警数据流

```mermaid
flowchart LR
    subgraph "数据采集"
        Traffic[网络流量] --> Suricata
        Suricata --> EVE[eve.json]
    end

    subgraph "数据处理"
        EVE --> Filebeat
        Filebeat --> Parser[日志解析器]
        Parser --> Enrich[数据丰富化]
        Enrich --> ES[(Elasticsearch)]
    end

    subgraph "数据消费"
        ES --> API[REST API]
        API --> WebUI[Web 界面]
        ES --> Kibana[Kibana<br/>可选]
    end

    subgraph "实时通道"
        Parser --> Redis[(Redis Pub/Sub)]
        Redis --> WSServer[WebSocket 服务]
        WSServer --> WebUI
    end
```

### 7.2 规则数据流

```mermaid
flowchart TB
    subgraph "规则来源"
        ETOpen[ET Open 规则源]
        Custom[自定义规则]
    end

    subgraph "规则处理"
        Download[下载规则包]
        Parse[解析规则文件]
        Validate[规则校验]
        Store[存储到数据库]
        Version[版本控制]
    end

    subgraph "规则部署"
        Merge[合并规则文件]
        Deploy[部署到 Suricata]
        Reload[重载规则]
        Verify[验证生效]
    end

    ETOpen --> Download
    Custom --> Parse
    Download --> Parse
    Parse --> Validate
    Validate --> Store
    Store --> Version

    Store --> Merge
    Merge --> Deploy
    Deploy --> Reload
    Reload --> Verify
```

---

## 8. 安全设计

### 8.1 安全架构

```mermaid
graph TB
    subgraph "访问控制"
        Auth[认证服务<br/>JWT Token]
        RBAC[角色权限<br/>Admin/Analyst/Viewer]
        Audit[操作审计日志]
    end

    subgraph "网络隔离"
        MgmtZone[管理网络区域]
        DetectZone[检测网络区域]
        TestZone[测试网络区域]
    end

    subgraph "数据安全"
        Encrypt[数据加密<br/>TLS/AES]
        Backup[数据备份]
        Retention[日志保留策略]
    end

    subgraph "攻击测试安全"
        Sandbox[沙箱隔离]
        RateLimit[速率限制]
        Allowlist[目标白名单]
    end

    Auth --> RBAC
    RBAC --> Audit

    MgmtZone --> DetectZone
    TestZone -.-> DetectZone

    Encrypt --> Backup
    Backup --> Retention

    Sandbox --> RateLimit
    RateLimit --> Allowlist
```

### 8.2 攻击测试安全措施

| 安全措施 | 实现方式 |
|----------|----------|
| 目标限制 | 只允许向预设的测试 IP/网段发送流量 |
| 流量隔离 | 使用独立的虚拟网卡进行测试 |
| 速率限制 | 限制单位时间内的测试请求数量 |
| 审计日志 | 记录所有测试操作和结果 |
| 权限控制 | 仅授权用户可执行攻击测试 |
| Payload 验证 | LLM 生成的 payload 需经过安全校验 |

---

## 9. 实现路线图

### 9.1 开发阶段规划

```mermaid
gantt
    title 项目开发路线图
    dateFormat  YYYY-MM-DD
    section 第一阶段 - 基础架构
    环境搭建与 Suricata 部署     :a1, 2024-02-01, 5d
    EVE 日志解析与存储           :a2, after a1, 5d
    基础 API 开发                :a3, after a2, 7d

    section 第二阶段 - 告警模块
    告警列表与详情页面           :b1, after a3, 5d
    告警-规则关联功能            :b2, after b1, 3d
    实时告警推送                 :b3, after b2, 3d

    section 第三阶段 - 规则管理
    规则解析与存储               :c1, after b3, 5d
    suricata-update 集成         :c2, after c1, 3d
    规则版本管理                 :c3, after c2, 5d
    规则更新调度                 :c4, after c3, 3d

    section 第四阶段 - 攻击测试
    规则解析引擎                 :d1, after c4, 5d
    Scapy 流量生成器             :d2, after d1, 7d
    测试执行与结果验证           :d3, after d2, 5d
    LLM 辅助集成（可选）          :d4, after d3, 7d

    section 第五阶段 - 优化完善
    性能优化                     :e1, after d4, 5d
    安全加固                     :e2, after e1, 5d
    文档与部署                   :e3, after e2, 5d
```

### 9.2 MVP 功能范围

**必须实现（P0）**：
- [ ] Suricata 部署与配置
- [ ] EVE JSON 告警解析与存储
- [ ] 告警列表查看与筛选
- [ ] 告警详情与规则关联
- [ ] ET Open 规则手动更新
- [ ] 规则列表查看

**应该实现（P1）**：
- [ ] 规则定时更新
- [ ] 规则版本管理
- [ ] 基础攻击测试（明确 content 规则）
- [ ] 实时告警推送

**可以实现（P2）**：
- [ ] LLM 辅助流量生成
- [ ] 复杂规则测试（PCRE）
- [ ] 威胁情报集成
- [ ] 多 Suricata 实例管理

---

## 10. 风险与挑战

### 10.1 技术风险

| 风险 | 影响 | 缓解措施 |
|------|------|----------|
| 高流量下性能问题 | Suricata/ES 过载 | 流量采样、集群部署 |
| 规则更新导致服务中断 | 检测中断 | 热重载、灰度更新 |
| 攻击测试误触发 | 影响生产环境 | 严格网络隔离 |
| LLM 生成不安全内容 | 安全风险 | 输出校验、沙箱执行 |

### 10.2 已知限制

1. **LLM 局限性**：
   - 无法保证生成的 payload 100% 触发规则
   - 复杂 PCRE 规则可能无法正确解析
   - 需要人工审核生成内容

2. **测试覆盖度**：
   - 部分规则依赖多包状态，单包测试无法触发
   - 加密流量规则无法通过明文流量测试

3. **规则兼容性**：
   - ET Open 规则可能与自定义规则冲突
   - 部分规则需要特定 Suricata 版本

---

## 11. 参考资源

### 官方文档
- [Suricata Documentation](https://docs.suricata.io/)
- [Suricata-Update Documentation](https://docs.suricata.io/en/latest/rule-management/suricata-update.html)
- [EVE JSON Format](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html)
- [Emerging Threats Open Rules](https://rules.emergingthreats.net/OPEN_download_instructions.html)

### 开源项目
- [Scirius (Stamus CE)](https://github.com/StamusNetworks/scirius) - Suricata 规则管理界面
- [SELKS](https://www.stamus-networks.com/selks) - 完整的 Suricata 安全平台
- [Suricata-Verify](https://github.com/OISF/suricata-verify) - Suricata 规则测试框架
- [sýnesis™ Lite](https://github.com/robcowart/synesis_lite_suricata) - Suricata + ELK 集成

### 相关研究
- [RulePilot: LLM-Powered Security Rule Generation](https://arxiv.org/html/2511.12224)
- [Elastic Suricata Integration](https://docs.elastic.co/en/integrations/suricata)

---

## 12. 结论

本方案基于成熟的开源技术栈，具有较高的可行性：

1. **告警管理**：通过 EVE JSON + Elasticsearch 实现高效的告警存储和查询
2. **规则管理**：利用 suricata-update 工具和 Git 版本控制实现完整的规则生命周期管理
3. **攻击测试**：结合 Scapy 流量生成和规则解析，可实现大部分规则的自动化测试
4. **LLM 辅助**：作为可选增强功能，在安全控制下辅助复杂规则的 payload 生成

建议采用渐进式开发策略，先完成核心功能（告警查看、规则管理），再逐步添加高级功能（攻击测试、LLM 集成）。
