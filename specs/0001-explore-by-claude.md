# 网络入侵检测系统 (NIDS) 技术研究

## 1. 网络入侵检测系统概述

### 1.1 什么是 NIDS

网络入侵检测系统 (Network-based Intrusion Detection System, NIDS) 是网络安全的关键组成部分，通过捕获和分析网络流量来检测潜在的入侵行为，如 DoS 攻击、端口扫描、僵尸网络等。

### 1.2 NIDS 部署模式

| 模式 | 描述 | 特点 |
|------|------|------|
| **Inline（内联）** | 直接位于网络路径中 | 可以实时阻断恶意流量，但可能影响网络性能 |
| **Passive（被动）** | 通过 TAP 或 SPAN 端口获取流量副本 | 不影响实际流量，但只能检测不能阻断 |

### 1.3 检测方法

1. **基于签名的检测 (Signature-based)**
   - 将收集的信息与签名数据库进行比对
   - 优点：准确率高，误报率低
   - 缺点：无法检测未知攻击（零日攻击）

2. **基于异常的检测 (Anomaly-based)**
   - 将当前行为与正常行为基线进行比较
   - 优点：可以检测未知攻击
   - 缺点：误报率较高，需要训练期

3. **基于协议的异常检测 (Protocol-based)**
   - 检测网络协议中的异常行为
   - 适用于检测协议滥用和畸形数据包

### 1.4 现代 NIDS 发展趋势

- **深度学习集成**：使用 CNN、LSTM、GAN 等算法提升检测能力
- **联邦学习**：解决计算成本和隐私风险问题
- **多层检测架构**：如 SE²CURA 系统的两层检测方案
- **SIEM 集成**：与安全信息和事件管理系统联动

---

## 2. Suricata 详解

### 2.1 概述

Suricata 是由 Open Information Security Foundation (OISF) 于 2009 年开发的开源网络威胁检测引擎。最新版本为 8.0.x（2025年）。

### 2.2 核心架构

#### 2.2.1 多线程架构

Suricata 最大的特点是采用**多线程设计**实现高性能处理。其架构由四个主要线程模块组成：

```
┌─────────────────────────────────────────────────────────────────┐
│                    Suricata 多线程架构                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌───────────────┐   ┌───────────────┐   ┌───────────────┐     │
│  │   Packet      │   │   Decode &    │   │   Detection   │     │
│  │  Acquisition  │──>│    Stream     │──>│    Engine     │     │
│  │               │   │  Application  │   │  (多线程)      │     │
│  └───────────────┘   └───────────────┘   └───────┬───────┘     │
│                                                   │             │
│                                                   v             │
│                                          ┌───────────────┐     │
│                                          │    Outputs    │     │
│                                          │   (告警处理)   │     │
│                                          └───────────────┘     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**四大线程模块**：

1. **Packet Acquisition（数据包采集）**
   - 负责从网络读取数据包
   - 支持多种采集方式：AF_PACKET、PF_RING、DPDK 等

2. **Decode and Stream Application Layer（解码与流应用层）**
   - 解码数据包
   - 检查应用层协议

3. **Detection（检测引擎）**
   - 进行签名比对
   - 可运行多个检测线程

4. **Outputs（输出模块）**
   - 处理所有告警和日志

#### 2.2.2 运行模式

| 模式 | 描述 |
|------|------|
| **single** | 单线程 pcap 实时模式 |
| **autofp** | 多线程 pcap 实时模式（自动流处理） |
| **workers** | 工作线程模式，每个线程处理完整的包处理流程 |

### 2.3 模式匹配算法

Suricata 的检测引擎核心是多模式匹配 (MPM) 算法：

| 算法 | 描述 | 适用场景 |
|------|------|----------|
| **AC** | Aho-Corasick（默认） | 通用场景 |
| **AC-BS** | Aho-Corasick 减少内存版 | 内存受限环境 |
| **AC-KS** | Aho-Corasick Ken Steele 变体 | 性能优化，推荐使用 |
| **HS (Hyperscan)** | Intel 开发的高性能匹配库 | 最佳性能（需编译支持） |

**Hyperscan 性能对比**：
- Emerging Threats 规则集：1.95 倍加速
- ET Pro 规则集：2.15 倍加速

### 2.4 主要功能特性

#### 2.4.1 深度包检测 (DPI)

- **协议识别**：HTTP、TLS/SSL、DNS、SSH、SMTP、FTP、SMB 等
- **端口无关检测**：协议检测不依赖端口配置
- **应用层解析**：深入分析应用层数据

#### 2.4.2 EVE JSON 输出

EVE (Extensible Event Format) 是 Suricata 的主要结构化日志机制：

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - files
        - flow
```

**支持的事件类型**：
- 告警 (alert)
- HTTP 请求/响应
- DNS 查询
- TLS/SSL 握手信息（支持 JA3/JA3S 指纹）
- 文件提取元数据
- 流量统计

#### 2.4.3 TLS 检测与日志

```yaml
tls:
  extended: yes
  custom:
    - subject
    - issuer
    - fingerprint
    - ja3
    - ja3s
    - certificate
```

#### 2.4.4 文件提取

支持从网络流量中提取传输的文件并进行分析。

### 2.5 规则格式

Suricata 规则与 Snort 规则格式兼容（有部分差异）：

```
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"ET MALWARE Suspicious User-Agent";
    flow:established,to_server;
    http.user_agent;
    content:"Mozilla/4.0";
    sid:2000001;
    rev:1;
)
```

### 2.6 性能优化配置

```yaml
# suricata.yaml
detect:
  profile: high
  custom-values:
    toclient-groups: 3
    toserver-groups: 25
  sgh-mpm-context: full
  inspection-recursion-limit: 3000

# 多模式匹配器配置
mpm-algo: ac-ks  # 或 hs（Hyperscan）
```

---

## 3. Snort 详解

### 3.1 概述

Snort 是世界上最流行的开源入侵检测/防御系统 (IDS/IPS)，由 Martin Roesch 于 1998 年创建，现由 Cisco Talos 维护。Snort 3 是最新的主要版本，进行了架构重写。

### 3.2 核心架构

#### 3.2.1 Snort 传统架构（四大组件）

```
┌─────────────────────────────────────────────────────────────────┐
│                     Snort 架构流程                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌───────────┐   ┌──────────────┐   ┌───────────┐   ┌────────┐ │
│  │  Sniffer  │──>│ Preprocessor │──>│ Detection │──>│ Output │ │
│  │  (嗅探器)  │   │  (预处理器)   │   │  Engine   │   │        │ │
│  └───────────┘   └──────────────┘   └───────────┘   └────────┘ │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

1. **Sniffer（嗅探器/解码器）**
   - 捕获原始网络数据包
   - 按协议层从下到上解码
   - 将解码数据保存到对应数据结构

2. **Preprocessor（预处理器）**
   - TCP 流重组
   - IP 分片重组
   - HTTP 请求规范化
   - 统计信息收集

3. **Detection Engine（检测引擎）**
   - 规则解析
   - 签名检测
   - 将数据包与规则集比对

4. **Output（输出）**
   - 生成告警
   - 记录日志

#### 3.2.2 Snort 3 架构改进

Snort 3 的主要架构变化：

| 特性 | Snort 2.x | Snort 3 |
|------|-----------|---------|
| **语言** | C | C++ |
| **线程** | 单线程 | 多线程支持 |
| **配置** | 复杂配置文件 | LuaJIT 脚本配置 |
| **预处理器** | Preprocessors | Inspectors |
| **插件** | 有限 | 200+ 插件接口 |

### 3.3 LibDAQ (Data Acquisition Library)

LibDAQ 是 Snort 的数据采集抽象层：

```
┌─────────────────────────────────────────────────────────────────┐
│                     LibDAQ 架构                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    Application (Snort)                   │   │
│  └─────────────────────────┬───────────────────────────────┘   │
│                            │                                    │
│  ┌─────────────────────────▼───────────────────────────────┐   │
│  │                     LibDAQ API                           │   │
│  └─────────────────────────┬───────────────────────────────┘   │
│                            │                                    │
│  ┌────────┬────────┬───────┴───┬────────┬────────┐            │
│  │  pcap  │afpacket│   nfq     │  dump  │  ...   │            │
│  │ Module │ Module │  Module   │ Module │ Modules│            │
│  └────────┴────────┴───────────┴────────┴────────┘            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**DAQ 模块类型**：
- **Base Modules**：完整的 DAQ 实现（如 pcap、afpacket）
- **Wrapper Modules**：装饰器模式的子集实现

**操作模式**：
- **Passive**：被动监控，只检测不阻断
- **Inline**：内联模式，可以阻断流量（使用 `-Q` 参数）

### 3.4 检测能力

#### 3.4.1 检测技术组合

- **签名检测**：基于规则的模式匹配
- **协议检测**：协议异常分析
- **异常检测**：偏离正常行为的检测

#### 3.4.2 可检测的攻击类型

- DoS/DDoS 攻击
- CGI 攻击
- 缓冲区溢出
- 隐蔽端口扫描
- SMB 探测
- 操作系统指纹识别

### 3.5 规则结构

Snort 规则由两部分组成：

```
# 规则头部                                    # 规则选项
alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"Web Attack";
                                             content:"/etc/passwd";
                                             sid:1000001;
                                             rev:1;)
```

**规则头部**：
- 动作（alert、log、pass、drop 等）
- 协议（tcp、udp、icmp、ip）
- 源/目标 IP 和端口
- 方向操作符（->、<>）

**规则选项**：
- `msg`：告警消息
- `content`：内容匹配
- `pcre`：正则表达式
- `flow`：流状态
- `sid`：规则 ID
- `rev`：修订版本

### 3.6 Snort 3 Inspector（检查器）

Snort 3 用 Inspector 替代了 Preprocessor：

| Inspector | 功能 |
|-----------|------|
| **http_inspect** | HTTP 协议分析 |
| **ssl** | SSL/TLS 检测 |
| **dns** | DNS 协议检测 |
| **stream** | TCP 流重组 |
| **normalizer** | 数据包规范化 |

### 3.7 OpenAppID

Snort 的应用层 DPI 功能：
- Layer 7 应用识别
- 检测社交媒体、流媒体、种子下载等流量
- 通过检查数据包头部信息工作

---

## 4. Suricata vs Snort 对比

### 4.1 功能对比表

| 特性 | Suricata | Snort 3 |
|------|----------|---------|
| **架构** | 原生多线程 | C++ 重写，支持多线程 |
| **性能** | 高流量环境优化 | 传统单线程性能稳定 |
| **协议检测** | 端口无关 | 依赖配置端口 |
| **输出格式** | EVE JSON（丰富） | 基础日志 |
| **规则兼容性** | 兼容大部分 Snort 规则 | 原生规则 |
| **资源消耗** | 较高（DPI、多线程） | 相对轻量 |
| **GPU 加速** | 支持 | 有限 |
| **Hyperscan 支持** | 原生支持 | 有限 |
| **文件提取** | 原生支持 | 需要额外配置 |
| **TLS 指纹** | JA3/JA3S 支持 | 有限 |

### 4.2 规则兼容性说明

Suricata 支持大部分 Snort 规则，但存在差异：
- 部分 Snort 规则需要调整才能在 Suricata 中使用
- 启用所有 Snort 规则类别可能导致数百条规则加载失败
- Suricata 有独特的规则选项（如 `http.user_agent` 粘性缓冲区）

### 4.3 使用场景建议

| 场景 | 推荐 | 原因 |
|------|------|------|
| 大型企业/高流量 | Suricata | 多线程、高性能 |
| 中小型组织 | Snort | 轻量、社区支持广 |
| 需要丰富日志分析 | Suricata | EVE JSON 输出 |
| 需要 IPS 功能 | 两者皆可 | 都支持内联模式 |
| 学习/教育目的 | Snort | 文档丰富、历史悠久 |

### 4.4 性能对比

```
                 吞吐量对比（示意）

    Suricata │████████████████████████████░░│ 高
             │                               │
    Snort 3  │████████████████████░░░░░░░░░░│ 中高
             │                               │
    Snort 2  │███████████████░░░░░░░░░░░░░░░│ 中
             └───────────────────────────────┘
              0%                          100%
```

---

## 5. 实现原理深入分析

### 5.1 数据包处理流程

```
                    网络数据包处理流程

    ┌──────────────┐
    │   Network    │
    │   Interface  │
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │    Capture   │  ← AF_PACKET / PCAP / PF_RING
    │              │
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │    Decode    │  ← Ethernet → IP → TCP/UDP
    │              │
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │   Defrag &   │  ← IP 分片重组
    │   Reassemble │  ← TCP 流重组
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │  Application │  ← HTTP/TLS/DNS 等协议解析
    │    Layer     │
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │   Detection  │  ← 签名匹配
    │    Engine    │
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │    Output    │  ← 告警/日志/阻断
    │              │
    └──────────────┘
```

### 5.2 签名匹配算法原理

#### 5.2.1 Aho-Corasick 算法

**核心思想**：构建有限状态自动机，一次扫描完成多模式匹配。

```
         构建模式树示例（模式：he, she, his, hers）

                    root
                   /    \
                  h      s
                 /|\      \
                e i s      h
               /  |  \      \
              r   s   [he]   e
             /                \
           [hers]            [she]
```

**时间复杂度**：O(n + m + z)
- n：文本长度
- m：模式总长度
- z：匹配数量

#### 5.2.2 Hyperscan 优化

Intel Hyperscan 的优势：
- SIMD 向量化加速
- 同时考虑 `depth` 和 `offset`
- 流模式支持跨数据包匹配

### 5.3 协议解析实现

以 HTTP 协议解析为例：

```c
// 伪代码示意
void http_parse(Flow *f, Packet *p) {
    // 1. 识别 HTTP 请求/响应
    if (is_http_request(p->payload)) {
        // 2. 解析方法、URI、版本
        parse_request_line(p);

        // 3. 解析头部
        parse_headers(p);

        // 4. 提取关键字段供检测引擎使用
        extract_uri(p);
        extract_user_agent(p);
        extract_host(p);
    }
}
```

---

## 6. 部署最佳实践

### 6.1 网络位置选择

- **边界防护点**：防火墙后、网关处
- **内部网段**：关键服务器区域
- **高流量点**：数据库、Web 服务器

### 6.2 性能调优建议

#### Suricata 调优

```yaml
# CPU 亲和性
threading:
  set-cpu-affinity: yes
  cpu-affinity:
    - management-cpu-set:
        cpu: [ 0 ]
    - receive-cpu-set:
        cpu: [ 1 ]
    - worker-cpu-set:
        cpu: [ 2, 3, 4, 5 ]

# 内存配置
detect:
  profile: high
```

#### Snort 调优

```lua
-- snort.lua
ips = {
    mode = inline,
    variables = default_variables,
    rules = [[
        include $RULE_PATH/snort3-community.rules
    ]]
}
```

### 6.3 规则集选择

| 规则集 | 特点 | 适用场景 |
|--------|------|----------|
| **Emerging Threats Open** | 免费、社区维护 | 通用检测 |
| **ET Pro** | 商业版、更新快 | 企业部署 |
| **Snort Community** | 官方社区规则 | Snort 用户 |
| **Snort Subscriber** | 订阅规则、30天提前获取 | 付费用户 |

---

## 7. 总结

### 7.1 技术选型建议

| 需求 | 建议方案 |
|------|----------|
| 高性能要求 | Suricata + Hyperscan |
| 资源受限 | Snort 3 |
| NSM 数据分析 | Suricata (EVE JSON) |
| 现有 Snort 基础设施 | 继续使用 Snort |
| 混合检测需求 | Suricata + Zeek 组合 |

### 7.2 未来发展方向

1. **机器学习/深度学习集成**
2. **云原生部署支持**
3. **容器化与 Kubernetes 集成**
4. **加密流量检测增强**
5. **联邦学习隐私保护检测**

---

## 8. 深度学习与 NIDS 集成

### 8.1 深度学习在入侵检测中的应用概述

传统的基于规则/签名的 IDS 面临以下挑战：
- 无法检测零日攻击
- 难以应对多态恶意软件
- 对高级持续性威胁 (APT) 检测能力有限

深度学习通过学习网络流量的复杂模式，能够有效弥补这些不足。

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    深度学习 IDS 系统架构                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐ │
│  │   Network   │   │    Data     │   │   Feature   │   │    Deep     │ │
│  │   Traffic   │──>│ Preprocess  │──>│  Extraction │──>│  Learning   │ │
│  │   Capture   │   │             │   │             │   │   Model     │ │
│  └─────────────┘   └─────────────┘   └─────────────┘   └──────┬──────┘ │
│                                                                │        │
│        ┌───────────────────────────────────────────────────────┘        │
│        │                                                                │
│        ▼                                                                │
│  ┌─────────────┐   ┌─────────────┐                                     │
│  │ Classification│   │   Alert/    │                                     │
│  │   Result    │──>│   Action    │                                     │
│  └─────────────┘   └─────────────┘                                     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 8.2 CNN (卷积神经网络) 在入侵检测中的应用

#### 8.2.1 核心原理

CNN 通过卷积层自动提取网络流量的空间特征，特别适合处理具有局部相关性的数据。

```
                CNN 入侵检测架构

    Input        Conv      Pool      Conv      Pool      FC      Output
    Layer        Layer     Layer     Layer     Layer     Layer   Layer

   ┌─────┐     ┌─────┐   ┌─────┐   ┌─────┐   ┌─────┐   ┌───┐   ┌─────┐
   │     │     │ ∗∗∗ │   │ max │   │ ∗∗∗ │   │ max │   │   │   │Normal│
   │ 7×7 │────>│ ∗∗∗ │──>│     │──>│ ∗∗∗ │──>│     │──>│ F │──>│Attack│
   │     │     │ ∗∗∗ │   │     │   │ ∗∗∗ │   │     │   │ C │   │ Type │
   └─────┘     └─────┘   └─────┘   └─────┘   └─────┘   └───┘   └─────┘

   网络流量      特征       降维      深层       降维     全连接   分类
   图像化       提取       采样      特征       采样      层      结果
```

#### 8.2.2 网络流量图像化方法

将网络流量转换为图像是 CNN 应用于入侵检测的关键步骤：

**方法 1：特征向量转灰度图**
```python
# 伪代码示例
def traffic_to_image(features, size=7):
    """
    将网络流量特征转换为灰度图像
    """
    # 1. 特征标准化到 [0, 255]
    normalized = normalize(features, min=0, max=255)

    # 2. 重塑为 size × size 图像
    image = normalized.reshape(size, size)

    return image
```

**方法 2：CiNeT 双向编码**
- 网络特征 (IPv4/IPv6、MAC、时间戳等) → RGB 表示
- 支持从检测结果反向追溯到原始数据包

**方法 3：字段到像素 (Field-to-Pixel)**
```
┌──────────────────────────────────────────────────┐
│  Packet Header Fields → Pixel Values             │
├──────────────────────────────────────────────────┤
│  src_ip    → pixel[0:4]                          │
│  dst_ip    → pixel[4:8]                          │
│  src_port  → pixel[8:10]                         │
│  dst_port  → pixel[10:12]                        │
│  protocol  → pixel[12]                           │
│  flags     → pixel[13:14]                        │
│  ...                                             │
└──────────────────────────────────────────────────┘
```

#### 8.2.3 典型 CNN 模型架构

**1D-CNN 架构（适用于原始流量数据）**：
```python
model = Sequential([
    Conv1D(64, kernel_size=3, activation='relu', input_shape=(n_features, 1)),
    BatchNormalization(),
    MaxPooling1D(pool_size=2),

    Conv1D(128, kernel_size=3, activation='relu'),
    BatchNormalization(),
    MaxPooling1D(pool_size=2),

    Flatten(),
    Dense(256, activation='relu'),
    Dropout(0.5),
    Dense(num_classes, activation='softmax')
])
```

**特征增强 CNN (FA-CNN)**：
- 使用互信息 (Mutual Information) 进行特征选择
- 输入数据增强额外选择的特征
- 在 NSL-KDD 和 CICIDS2017 上表现优异

#### 8.2.4 性能数据

| 模型 | 数据集 | 准确率 | 备注 |
|------|--------|--------|------|
| 1D-CNN | IoT 数据集 | 99.12% | 最高准确率 |
| CNN-MLP 混合 | IoT-23 | 99.94% | 二分类 |
| CNN-MLP 混合 | NF-BoT-IoT-v2 | 99.96% | 二分类 |
| ICNN-ID (LeNet) | NSL-KDD | 89.97% | 多分类 |
| ICNN-ID (LeNet) | CICIoV2024 | 99.996% | 多分类 |

---

### 8.3 LSTM/RNN 在入侵检测中的应用

#### 8.3.1 核心原理

LSTM (Long Short-Term Memory) 是一种特殊的 RNN，专门解决长序列依赖问题，非常适合分析网络流量的时序特征。

```
                    LSTM 单元结构

         ┌─────────────────────────────────────────┐
         │              Cell State                 │
         │    ─────────────────────────────────>   │
         │         ×           +                   │
         │         │           │                   │
         │    ┌────┴───┐  ┌────┴────┐  ┌────────┐ │
         │    │ Forget │  │  Input  │  │ Output │ │
         │    │  Gate  │  │  Gate   │  │  Gate  │ │
         │    │   σ    │  │  σ tanh │  │   σ    │ │
         │    └────┬───┘  └────┬────┘  └────┬───┘ │
         │         │           │            │      │
         │    ─────┴───────────┴────────────┴──>   │
         │              Hidden State               │
         └─────────────────────────────────────────┘

    遗忘门：决定丢弃哪些信息
    输入门：决定存储哪些新信息
    输出门：决定输出哪些信息
```

#### 8.3.2 LSTM 适用场景

- **时序依赖分析**：网络流量具有时间序列特性
- **长期模式识别**：检测跨越多个数据包的攻击
- **状态跟踪**：维护会话状态信息

#### 8.3.3 混合架构：CNN-LSTM

结合 CNN 的空间特征提取和 LSTM 的时序建模能力：

```
┌─────────────────────────────────────────────────────────────────┐
│                    CNN-LSTM 混合架构                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐        │
│  │  Input  │   │   CNN   │   │  LSTM   │   │  Dense  │        │
│  │ Sequence│──>│ (空间)   │──>│ (时序)  │──>│ (分类)  │        │
│  └─────────┘   └─────────┘   └─────────┘   └─────────┘        │
│                                                                 │
│  流量序列 ──> 空间特征提取 ──> 时序依赖建模 ──> 攻击分类          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Attention-CNN-LSTM 模型**：
```python
# 伪代码示例
class AttentionCNNLSTM(nn.Module):
    def __init__(self):
        self.cnn = CNN_Block()           # 空间特征提取
        self.lstm = LSTM_Block()         # 时序建模
        self.attention = SelfAttention() # 注意力机制
        self.classifier = Dense()        # 分类层

    def forward(self, x):
        spatial_features = self.cnn(x)
        temporal_features = self.lstm(spatial_features)
        attended = self.attention(temporal_features)
        output = self.classifier(attended)
        return output
```

#### 8.3.4 性能数据

| 模型 | 数据集 | 准确率 | 精确率 | 召回率 |
|------|--------|--------|--------|--------|
| Attention-CNN-LSTM | NSL-KDD | 94.8-97.5% | - | - |
| LSTM-CNN | IoT 数据集 | 99.87% | 99.89% | 99.85% |
| 优化 LSTM | NSL-KDD | 高 | - | - |
| LSTM | CIC IoT | 98.98% | - | - |

---

### 8.4 GAN (生成对抗网络) 在入侵检测中的应用

#### 8.4.1 核心原理

GAN 由生成器 (Generator) 和判别器 (Discriminator) 组成，通过对抗训练生成逼真的数据。

```
                    GAN 基本架构

    ┌─────────────┐                    ┌─────────────┐
    │   Random    │                    │    Real     │
    │   Noise z   │                    │   Samples   │
    └──────┬──────┘                    └──────┬──────┘
           │                                  │
           ▼                                  │
    ┌─────────────┐                           │
    │  Generator  │                           │
    │      G      │                           │
    └──────┬──────┘                           │
           │                                  │
           ▼                                  ▼
    ┌─────────────┐                    ┌─────────────┐
    │   Fake      │                    │             │
    │  Samples    │───────────────────>│Discriminator│──> Real/Fake
    └─────────────┘                    │      D      │
                                       └─────────────┘

    G 目标：生成能欺骗 D 的假样本
    D 目标：正确区分真假样本
```

#### 8.4.2 GAN 在 IDS 中的主要应用

**1. 数据增强（解决类别不平衡）**

网络入侵数据集通常存在严重的类别不平衡问题：

```
原始数据分布:
┌─────────────────────────────────────────────────────────────┐
│ Normal:    ████████████████████████████████████████ 95%     │
│ DoS:       ████                                      3%      │
│ Probe:     █                                         1%      │
│ R2L:       ░                                         0.5%    │
│ U2R:       ░                                         0.5%    │
└─────────────────────────────────────────────────────────────┘

GAN 增强后:
┌─────────────────────────────────────────────────────────────┐
│ Normal:    ████████████████████████████████████████ 50%     │
│ DoS:       ████████████████████████                 25%     │
│ Probe:     ████████████                             12.5%   │
│ R2L:       ██████                                    6.25%  │
│ U2R:       ██████                                    6.25%  │
└─────────────────────────────────────────────────────────────┘
```

**2. 异常检测**

训练 GAN 只学习正常流量模式，异常流量将产生高重建误差。

**3. 对抗训练**

使用 GAN 生成对抗样本，增强模型的鲁棒性。

#### 8.4.3 常用 GAN 变体

| GAN 类型 | 特点 | 应用场景 |
|----------|------|----------|
| **Vanilla GAN** | 基础版本 | 简单数据增强 |
| **WGAN** | Wasserstein 距离 | 训练更稳定 |
| **WGAN-GP** | 梯度惩罚 | 防止模式崩溃 |
| **CGAN** | 条件生成 | 指定攻击类型生成 |
| **CTGAN** | 表格数据专用 | 网络流量特征生成 |
| **VAE-WACGAN** | VAE + WGAN + AC | 高质量样本生成 |

#### 8.4.4 VAE-WACGAN 模型架构

```
┌─────────────────────────────────────────────────────────────────┐
│                    VAE-WACGAN 架构                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────┐   ┌─────────┐   ┌─────────────────────────────┐   │
│  │ Encoder │──>│ Latent  │──>│       Generator (G)         │   │
│  │  (VAE)  │   │  Space  │   │  + Auxiliary Classifier     │   │
│  └─────────┘   └─────────┘   └──────────────┬──────────────┘   │
│                                              │                  │
│                                              ▼                  │
│                                    ┌─────────────────┐         │
│                                    │ Discriminator   │         │
│                                    │ + Wasserstein   │         │
│                                    │ + Gradient Pen. │         │
│                                    └─────────────────┘         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### 8.4.5 性能提升效果

- GAN 数据增强可提升 F1-score **10-15%**
- 假阴性率降低高达 **22%**
- 在少数类攻击检测上效果显著

---

### 8.5 Transformer 与注意力机制

#### 8.5.1 核心原理

Transformer 基于自注意力机制，能够捕获输入序列中任意位置之间的依赖关系。

```
                Multi-Head Self-Attention

    Input: [x₁, x₂, x₃, ..., xₙ]
                    │
            ┌───────┼───────┐
            ▼       ▼       ▼
          ┌───┐   ┌───┐   ┌───┐
          │ Q │   │ K │   │ V │
          └─┬─┘   └─┬─┘   └─┬─┘
            │       │       │
            └───────┼───────┘
                    ▼
         ┌─────────────────────┐
         │  Attention(Q,K,V)   │
         │  = softmax(QKᵀ/√d)V │
         └─────────────────────┘
                    │
                    ▼
              Attended Output
```

#### 8.5.2 BERT 在入侵检测中的应用

BERT (Bidirectional Encoder Representations from Transformers) 的双向编码特性使其能够同时考虑前后文信息：

```python
# BERT-based IDS 伪代码
class BERT_IDS:
    def __init__(self):
        self.tokenizer = BERTTokenizer()
        self.encoder = BERTEncoder(max_length=256)
        self.classifier = Dense(num_classes)

    def preprocess(self, traffic_features):
        # 将网络特征转换为 token 序列
        tokens = self.tokenizer.encode(traffic_features)
        return tokens

    def predict(self, traffic):
        tokens = self.preprocess(traffic)
        embeddings = self.encoder(tokens)
        prediction = self.classifier(embeddings)
        return prediction
```

#### 8.5.3 混合 Transformer 架构

**CNN-BiLSTM-Transformer**：
```
┌─────────────────────────────────────────────────────────────────┐
│              CNN-BiLSTM-Transformer 架构                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Input ──> [CNN] ──> [BiLSTM] ──> [Transformer] ──> Output     │
│             │          │              │                         │
│          空间特征    双向时序      自注意力                       │
│          提取       建模         全局依赖                        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**ADFCNN-BiLSTM（可变形卷积 + 注意力）**：
- 使用可变形卷积自适应提取空间特征
- 从通道和空间两个维度关注重要特征

#### 8.5.4 应用场景

| 场景 | 模型选择 | 优势 |
|------|----------|------|
| 云环境 | Transformer-based | 处理大规模分布式流量 |
| 5G/6G 网络 | Dynamic Semantic Embedding + Transformer | 动态语义特征捕获 |
| IoT 设备 | DistilBERT / Fine-tuned BERT | 轻量化部署 |
| 实时检测 | Attention-CNN-LSTM | 平衡性能与效率 |

---

### 8.6 与传统 IDS 集成架构

#### 8.6.1 混合 IDS 架构

将深度学习与 Suricata/Snort 结合的混合架构：

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         混合 NIDS 架构                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────┐                                                        │
│  │   Network   │                                                        │
│  │   Traffic   │                                                        │
│  └──────┬──────┘                                                        │
│         │                                                               │
│         ▼                                                               │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    Suricata / Snort                              │   │
│  │  ┌───────────┐   ┌───────────┐   ┌───────────┐                  │   │
│  │  │  Capture  │──>│  Decode   │──>│ Signature │──> Alerts        │   │
│  │  └───────────┘   └───────────┘   │  Matching │    (已知威胁)     │   │
│  │                                   └───────────┘                  │   │
│  └─────────────────────────┬───────────────────────────────────────┘   │
│                            │                                            │
│                            │ EVE JSON / Logs                            │
│                            ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                   Deep Learning Module                           │   │
│  │  ┌───────────┐   ┌───────────┐   ┌───────────┐                  │   │
│  │  │   Data    │──>│  Feature  │──>│   DL      │──> Alerts        │   │
│  │  │  Preproc  │   │ Extraction│   │  Model    │    (未知威胁)     │   │
│  │  └───────────┘   └───────────┘   └───────────┘                  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│                            │                                            │
│                            ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                   Alert Correlation / SIEM                       │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

#### 8.6.2 集成方式

**方式 1：离线分析**
```
Suricata ──> EVE JSON ──> 离线处理 ──> DL 模型训练/推理
```

**方式 2：实时管道**
```
Suricata ──> Kafka/Redis ──> 实时特征提取 ──> DL 推理 ──> 告警
```

**方式 3：嵌入式集成**
```python
# 与 Suricata EVE 日志集成示例
import json
from kafka import KafkaConsumer
from model import DeepLearningIDS

consumer = KafkaConsumer('suricata-eve')
model = DeepLearningIDS.load('trained_model.h5')

for message in consumer:
    eve_log = json.loads(message.value)

    # 提取特征
    features = extract_features(eve_log)

    # DL 预测
    prediction = model.predict(features)

    if prediction['is_anomaly']:
        generate_alert(eve_log, prediction)
```

#### 8.6.3 数据预处理管道

```
┌─────────────────────────────────────────────────────────────────┐
│                    数据预处理流程                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Raw Traffic                                                    │
│      │                                                          │
│      ▼                                                          │
│  ┌─────────────────────────────────────────┐                   │
│  │ 1. 数据清洗                              │                   │
│  │    - 去除噪声、缺失值处理                 │                   │
│  │    - 处理不一致/冗余数据                  │                   │
│  └─────────────────────────────────────────┘                   │
│      │                                                          │
│      ▼                                                          │
│  ┌─────────────────────────────────────────┐                   │
│  │ 2. 特征类型转换                          │                   │
│  │    - 分类特征 → Label Encoding           │                   │
│  │    - 避免维度爆炸                         │                   │
│  └─────────────────────────────────────────┘                   │
│      │                                                          │
│      ▼                                                          │
│  ┌─────────────────────────────────────────┐                   │
│  │ 3. 特征归一化                            │                   │
│  │    - Min-Max Scaling: [0, 1]            │                   │
│  │    - Log Normalization                   │                   │
│  │    - Z-Score Standardization             │                   │
│  └─────────────────────────────────────────┘                   │
│      │                                                          │
│      ▼                                                          │
│  ┌─────────────────────────────────────────┐                   │
│  │ 4. 特征选择                              │                   │
│  │    - Information Gain                    │                   │
│  │    - Mutual Information                  │                   │
│  │    - 前向/后向选择                        │                   │
│  └─────────────────────────────────────────┘                   │
│      │                                                          │
│      ▼                                                          │
│  ┌─────────────────────────────────────────┐                   │
│  │ 5. 数据转换（可选）                       │                   │
│  │    - 转换为图像 (CNN)                    │                   │
│  │    - 转换为序列 (LSTM)                   │                   │
│  │    - Token 化 (Transformer)              │                   │
│  └─────────────────────────────────────────┘                   │
│      │                                                          │
│      ▼                                                          │
│  Processed Features for DL Model                                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

### 8.7 常用数据集

| 数据集 | 年份 | 特点 | 攻击类型 |
|--------|------|------|----------|
| **NSL-KDD** | 2009 | 经典基准数据集 | DoS, Probe, R2L, U2R |
| **UNSW-NB15** | 2015 | 现代攻击类型 | Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms |
| **CICIDS2017** | 2017 | 真实流量模拟 | Brute Force, Heartbleed, Botnet, DoS, DDoS, Web Attacks, Infiltration |
| **CSE-CIC-IDS2018** | 2018 | 大规模数据集 | 同 CICIDS2017 + 新攻击 |
| **IoT-23** | 2020 | IoT 专用 | Botnet, DDoS, Port Scan |
| **CICIoT2023** | 2023 | 最新 IoT 数据 | 33 种攻击类型 |
| **CICIoV2024** | 2024 | 车联网数据 | 车辆网络攻击 |

---

### 8.8 模型选择指南

```
                        模型选择决策树

                    ┌─────────────────┐
                    │   任务需求是？   │
                    └────────┬────────┘
                             │
            ┌────────────────┼────────────────┐
            ▼                ▼                ▼
    ┌───────────────┐ ┌───────────────┐ ┌───────────────┐
    │ 空间特征为主   │ │ 时序特征为主   │ │ 数据不平衡    │
    │               │ │               │ │               │
    │   选择 CNN    │ │ 选择 LSTM/RNN │ │   选择 GAN    │
    └───────┬───────┘ └───────┬───────┘ └───────┬───────┘
            │                 │                 │
            ▼                 ▼                 ▼
    ┌───────────────┐ ┌───────────────┐ ┌───────────────┐
    │ 需要时序？     │ │ 需要空间？     │ │ 数据增强后    │
    │ → CNN-LSTM    │ │ → CNN-LSTM    │ │ 选择主模型    │
    └───────────────┘ └───────────────┘ └───────────────┘
                             │
                             ▼
                    ┌───────────────┐
                    │ 需要全局依赖？ │
                    │ → Transformer │
                    └───────────────┘
```

| 场景 | 推荐模型 | 原因 |
|------|----------|------|
| 资源受限环境 | 1D-CNN | 计算效率高 |
| 高精度需求 | CNN-LSTM + Attention | 综合性能最佳 |
| 严重类别不平衡 | GAN 增强 + 主模型 | 解决数据问题 |
| 大规模部署 | DistilBERT | 轻量化 Transformer |
| 长序列分析 | BiLSTM + Transformer | 长程依赖建模 |
| 实时检测 | 轻量 CNN | 低延迟 |

---

### 8.9 实现框架与工具

| 框架/工具 | 用途 | 特点 |
|-----------|------|------|
| **TensorFlow/Keras** | 模型训练 | 生产环境友好 |
| **PyTorch** | 模型研究 | 灵活性高 |
| **Scikit-learn** | 预处理/评估 | 全面的工具集 |
| **CICFlowMeter** | 流量特征提取 | CICIDS 数据集配套 |
| **Zeek (Bro)** | 流量分析 | 丰富的协议解析 |
| **Weights & Biases** | 实验跟踪 | 可视化训练过程 |

---

## 参考资料

### 传统 IDS 参考

- [Suricata Official Documentation](https://docs.suricata.io/)
- [Snort Official Website](https://www.snort.org/)
- [LibDAQ GitHub Repository](https://github.com/snort3/libdaq)
- [Suricata Features](https://suricata.io/features/)
- [Snort 3 Rule Writing Guide](https://docs.snort.org/)
- [StationX - Suricata vs Snort Comparison](https://www.stationx.net/suricata-vs-snort/)
- [Stamus Networks - Suricata vs Snort](https://www.stamus-networks.com/suricata-vs-snort)
- [Fidelis Security - NIDS Guide](https://fidelissecurity.com/threatgeek/network-security/resilient-network-defense-with-nids/)
- [LevelBlue - Suricata Threading Overview](https://cybersecurity.att.com/blogs/security-essentials/suricata-ids-threading-capabilities-overview)

### 深度学习 IDS 参考

- [Deep Learning for Network Security: Attention-CNN-LSTM Model](https://www.nature.com/articles/s41598-025-07706-y) - Scientific Reports, 2025
- [Optimized LSTM-Based Deep Learning Model for Anomaly Network Intrusion Detection](https://www.nature.com/articles/s41598-025-85248-z) - Scientific Reports, 2025
- [Hybrid CNN-LSTM Approach for Intelligent Cyber Intrusion Detection](https://www.sciencedirect.com/science/article/abs/pii/S0167404824004516) - Computers & Security, 2024
- [Future of GAN for Anomaly Detection in Network Security](https://www.sciencedirect.com/science/article/pii/S0167404824000348) - ScienceDirect, 2024
- [Enhancing Network Intrusion Detection Using GANs](https://www.sciencedirect.com/science/article/abs/pii/S0167404824003109) - ScienceDirect, 2024
- [Transformers and LLMs for Efficient IDS](https://arxiv.org/html/2408.07583v2) - arXiv Survey
- [BERT-based Network for Intrusion Detection](https://jis-eurasipjournals.springeropen.com/articles/10.1186/s13635-025-00191-w) - EURASIP Journal, 2025
- [Bijective Network-to-Image Encoding (CiNeT)](https://www.mdpi.com/2673-8732/5/4/42) - MDPI
- [Image-Based IDS with CNN](https://github.com/choidslab/image-based-ids) - GitHub
- [VAE-WACGAN Data Augmentation for IDS](https://www.mdpi.com/1424-8220/24/18/6035) - Sensors, 2024
- [A Suricata and ML Based Hybrid NIDS](https://link.springer.com/chapter/10.1007/978-3-030-91738-8_43) - Springer
