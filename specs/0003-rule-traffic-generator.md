# 基于规则解析的测试流量生成器实现方案

## 1. 核心原理

### 1.1 为什么可以自动生成

Suricata 规则本质上是**声明式的匹配条件**，规则明确定义了：
- 匹配什么协议
- 匹配什么内容（content）
- 内容在什么位置（offset、depth）
- 内容满足什么模式（pcre）

**逆向思维**：既然规则定义了"什么流量会触发告警"，那么我们只需要**构造满足这些条件的流量**即可。

```
┌─────────────────────────────────────────────────────────────────┐
│                        核心原理                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Suricata 规则                    测试流量                      │
│   ─────────────                   ─────────                     │
│                                                                 │
│   content:"malware"      ──────>  payload 包含 "malware"        │
│                                                                 │
│   http.uri; content:"/admin"  ──>  HTTP URI = "/admin"          │
│                                                                 │
│   pcre:"/user\d+/"       ──────>  exrex 生成 "user123"          │
│                                                                 │
│   dsize:>100             ──────>  payload 长度 > 100            │
│                                                                 │
│   flow:established       ──────>  先完成 TCP 三次握手            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 规则结构分析

```
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"ET MALWARE Suspicious UA";       ← 告警消息（不影响匹配）
    flow:established,to_server;           ← 流状态要求
    content:"GET";                        ← 必须包含的内容
    http.method;                          ← 上一个 content 匹配 HTTP 方法
    content:"/download/";                 ← 必须包含的内容
    http.uri;                             ← 上一个 content 匹配 HTTP URI
    content:"malware";                    ← 必须包含的内容
    http.user_agent;                      ← 上一个 content 匹配 User-Agent
    pcre:"/(?:wget|curl)/i";              ← 正则匹配
    http.user_agent;                      ← 正则匹配 User-Agent
    sid:2024001;                          ← 规则 ID
    rev:1;                                ← 版本
)
```

**从这条规则可以提取的构造要求**：
1. 协议：HTTP
2. 方向：client → server
3. 需要 TCP 已建立连接
4. HTTP Method = "GET"
5. HTTP URI 包含 "/download/"
6. User-Agent 包含 "malware" 且匹配 `wget` 或 `curl`

---

## 2. 系统架构

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         流量生成器架构                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │   Rule      │    │   Rule      │    │  Traffic    │    │   Packet    │  │
│  │   Input     │───>│   Parser    │───>│  Builder    │───>│   Sender    │  │
│  │             │    │             │    │             │    │             │  │
│  └─────────────┘    └──────┬──────┘    └──────┬──────┘    └─────────────┘  │
│                            │                  │                             │
│                            v                  v                             │
│                    ┌─────────────┐    ┌─────────────┐                      │
│                    │  Parsed     │    │  Protocol   │                      │
│                    │  Rule       │    │  Handlers   │                      │
│                    │  Structure  │    │             │                      │
│                    └─────────────┘    ├─────────────┤                      │
│                                       │ HTTP Handler│                      │
│                                       │ TCP Handler │                      │
│                                       │ UDP Handler │                      │
│                                       │ DNS Handler │                      │
│                                       │ ICMP Handler│                      │
│                                       └─────────────┘                      │
│                                                                             │
│                    ┌─────────────┐    ┌─────────────┐                      │
│                    │   PCRE      │    │   Sample    │                      │
│                    │   Reverser  │    │   Library   │                      │
│                    │   (exrex)   │    │             │                      │
│                    └─────────────┘    └─────────────┘                      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. 详细实现

### 3.1 规则解析器

```python
"""
rule_parser.py - Suricata 规则解析器
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Tuple
from enum import Enum


class Protocol(Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    IP = "ip"
    HTTP = "http"
    DNS = "dns"
    TLS = "tls"
    SSH = "ssh"
    FTP = "ftp"
    SMTP = "smtp"


class FlowDirection(Enum):
    TO_SERVER = "to_server"
    TO_CLIENT = "to_client"
    FROM_SERVER = "from_server"
    FROM_CLIENT = "from_client"


@dataclass
class ContentMatch:
    """content 关键字匹配项"""
    value: bytes                          # 原始内容（处理转义后）
    raw_value: str                        # 原始字符串
    nocase: bool = False                  # 大小写不敏感
    offset: Optional[int] = None          # 起始偏移
    depth: Optional[int] = None           # 搜索深度
    distance: Optional[int] = None        # 与上一个 content 的距离
    within: Optional[int] = None          # 在上一个 content 之后的范围内
    fast_pattern: bool = False            # 快速模式
    # HTTP 缓冲区绑定
    http_method: bool = False
    http_uri: bool = False
    http_raw_uri: bool = False
    http_header: bool = False
    http_raw_header: bool = False
    http_cookie: bool = False
    http_user_agent: bool = False
    http_host: bool = False
    http_content_type: bool = False
    http_request_body: bool = False
    http_response_body: bool = False
    http_stat_code: bool = False
    http_stat_msg: bool = False
    # 其他缓冲区
    dns_query: bool = False
    tls_sni: bool = False


@dataclass
class PCREMatch:
    """pcre 关键字匹配项"""
    pattern: str                          # 正则表达式
    modifiers: str = ""                   # 修饰符 (i, s, m, etc.)
    # 缓冲区绑定
    http_method: bool = False
    http_uri: bool = False
    http_header: bool = False
    http_user_agent: bool = False
    http_host: bool = False
    http_request_body: bool = False
    relative: bool = False                # R 修饰符，相对位置


@dataclass
class FlowOptions:
    """flow 关键字选项"""
    established: bool = False
    not_established: bool = False
    stateless: bool = False
    to_server: bool = False
    to_client: bool = False
    from_server: bool = False
    from_client: bool = False


@dataclass
class ParsedRule:
    """解析后的规则结构"""
    # 基本信息
    action: str                           # alert, log, pass, drop, reject
    protocol: Protocol
    src_ip: str
    src_port: str
    direction: str                        # -> 或 <>
    dst_ip: str
    dst_port: str

    # 元数据
    sid: int = 0
    rev: int = 1
    msg: str = ""
    classtype: str = ""
    priority: int = 3
    metadata: Dict[str, Any] = field(default_factory=dict)

    # 检测选项
    contents: List[ContentMatch] = field(default_factory=list)
    pcres: List[PCREMatch] = field(default_factory=list)
    flow: Optional[FlowOptions] = None

    # 大小约束
    dsize: Optional[str] = None           # 如 ">100", "<500", "100<>500"
    urilen: Optional[str] = None

    # 其他选项
    flags: Optional[str] = None           # TCP flags
    ttl: Optional[str] = None
    tos: Optional[str] = None
    itype: Optional[int] = None           # ICMP type
    icode: Optional[int] = None           # ICMP code

    # 原始规则
    raw_rule: str = ""

    # 生成状态
    can_auto_generate: bool = True
    unsupported_reason: str = ""


class SuricataRuleParser:
    """Suricata 规则解析器"""

    # 规则头部正则
    HEADER_REGEX = re.compile(
        r'^(alert|log|pass|drop|reject|rejectsrc|rejectdst|rejectboth)\s+'
        r'(tcp|udp|icmp|ip|http|ftp|tls|ssh|smtp|dns|dcerpc|smb|nfs|dhcp)\s+'
        r'(\S+)\s+'           # src_ip
        r'(\S+)\s+'           # src_port
        r'(->|<>)\s+'         # direction
        r'(\S+)\s+'           # dst_ip
        r'(\S+)\s*'           # dst_port
        r'\((.+)\)\s*$',      # options
        re.IGNORECASE | re.DOTALL
    )

    def parse(self, rule_text: str) -> ParsedRule:
        """解析单条规则"""
        rule_text = rule_text.strip()

        # 移除注释
        if rule_text.startswith('#'):
            raise ValueError("Commented rule")

        # 解析头部
        match = self.HEADER_REGEX.match(rule_text)
        if not match:
            raise ValueError(f"Cannot parse rule header: {rule_text[:80]}...")

        action = match.group(1).lower()
        protocol_str = match.group(2).lower()
        src_ip = match.group(3)
        src_port = match.group(4)
        direction = match.group(5)
        dst_ip = match.group(6)
        dst_port = match.group(7)
        options_str = match.group(8)

        # 映射协议
        try:
            protocol = Protocol(protocol_str)
        except ValueError:
            protocol = Protocol.TCP  # 默认

        # 创建规则对象
        rule = ParsedRule(
            action=action,
            protocol=protocol,
            src_ip=src_ip,
            src_port=src_port,
            direction=direction,
            dst_ip=dst_ip,
            dst_port=dst_port,
            raw_rule=rule_text
        )

        # 解析选项
        self._parse_options(options_str, rule)

        # 检查是否可以自动生成
        self._check_auto_generate(rule)

        return rule

    def _parse_options(self, options_str: str, rule: ParsedRule):
        """解析规则选项部分"""

        # 提取 sid
        sid_match = re.search(r'sid:\s*(\d+)', options_str)
        if sid_match:
            rule.sid = int(sid_match.group(1))

        # 提取 rev
        rev_match = re.search(r'rev:\s*(\d+)', options_str)
        if rev_match:
            rule.rev = int(rev_match.group(1))

        # 提取 msg
        msg_match = re.search(r'msg:\s*"([^"]*)"', options_str)
        if msg_match:
            rule.msg = msg_match.group(1)

        # 提取 classtype
        classtype_match = re.search(r'classtype:\s*([^;]+)', options_str)
        if classtype_match:
            rule.classtype = classtype_match.group(1).strip()

        # 提取 flow
        flow_match = re.search(r'flow:\s*([^;]+)', options_str)
        if flow_match:
            rule.flow = self._parse_flow(flow_match.group(1))

        # 提取 dsize
        dsize_match = re.search(r'dsize:\s*([^;]+)', options_str)
        if dsize_match:
            rule.dsize = dsize_match.group(1).strip()

        # 提取 urilen
        urilen_match = re.search(r'urilen:\s*([^;]+)', options_str)
        if urilen_match:
            rule.urilen = urilen_match.group(1).strip()

        # 提取 TCP flags
        flags_match = re.search(r'flags:\s*([^;]+)', options_str)
        if flags_match:
            rule.flags = flags_match.group(1).strip()

        # 提取 ICMP type/code
        itype_match = re.search(r'itype:\s*(\d+)', options_str)
        if itype_match:
            rule.itype = int(itype_match.group(1))
        icode_match = re.search(r'icode:\s*(\d+)', options_str)
        if icode_match:
            rule.icode = int(icode_match.group(1))

        # 提取所有 content（按顺序，保留位置关系）
        rule.contents = self._parse_contents(options_str)

        # 提取所有 pcre
        rule.pcres = self._parse_pcres(options_str)

    def _parse_contents(self, options_str: str) -> List[ContentMatch]:
        """按顺序解析所有 content"""
        contents = []

        # 使用状态机解析，保持顺序和修饰符关联
        # 分割选项（注意处理嵌套引号）
        tokens = self._tokenize_options(options_str)

        current_content = None

        for token in tokens:
            token = token.strip()

            # content 关键字
            content_match = re.match(r'content:\s*(!?)"([^"]*)"', token)
            if content_match:
                # 保存上一个 content
                if current_content:
                    contents.append(current_content)

                negated = content_match.group(1) == '!'
                raw_value = content_match.group(2)

                current_content = ContentMatch(
                    value=self._unescape_content(raw_value),
                    raw_value=raw_value,
                )
                continue

            # content 修饰符
            if current_content:
                if token == 'nocase':
                    current_content.nocase = True
                elif token.startswith('offset:'):
                    current_content.offset = int(re.search(r'\d+', token).group())
                elif token.startswith('depth:'):
                    current_content.depth = int(re.search(r'\d+', token).group())
                elif token.startswith('distance:'):
                    current_content.distance = int(re.search(r'-?\d+', token).group())
                elif token.startswith('within:'):
                    current_content.within = int(re.search(r'\d+', token).group())
                elif token == 'fast_pattern':
                    current_content.fast_pattern = True
                # HTTP 缓冲区
                elif token in ('http.method', 'http_method'):
                    current_content.http_method = True
                elif token in ('http.uri', 'http_uri'):
                    current_content.http_uri = True
                elif token in ('http.uri.raw', 'http_raw_uri'):
                    current_content.http_raw_uri = True
                elif token in ('http.header', 'http_header'):
                    current_content.http_header = True
                elif token in ('http.header.raw', 'http_raw_header'):
                    current_content.http_raw_header = True
                elif token in ('http.cookie', 'http_cookie'):
                    current_content.http_cookie = True
                elif token in ('http.user_agent', 'http_user_agent'):
                    current_content.http_user_agent = True
                elif token in ('http.host', 'http_host'):
                    current_content.http_host = True
                elif token in ('http.content_type', 'http_content_type'):
                    current_content.http_content_type = True
                elif token in ('http.request_body', 'http_client_body'):
                    current_content.http_request_body = True
                elif token in ('http.response_body', 'http_server_body', 'file_data'):
                    current_content.http_response_body = True
                elif token in ('http.stat_code', 'http_stat_code'):
                    current_content.http_stat_code = True
                elif token in ('http.stat_msg', 'http_stat_msg'):
                    current_content.http_stat_msg = True
                elif token in ('dns.query', 'dns_query'):
                    current_content.dns_query = True
                elif token in ('tls.sni', 'tls_sni'):
                    current_content.tls_sni = True

        # 保存最后一个 content
        if current_content:
            contents.append(current_content)

        return contents

    def _parse_pcres(self, options_str: str) -> List[PCREMatch]:
        """解析所有 pcre"""
        pcres = []

        # 匹配 pcre:"/pattern/modifiers"
        for match in re.finditer(r'pcre:\s*"(/[^"]+)"', options_str):
            pcre_str = match.group(1)

            # 解析 /pattern/modifiers
            pcre_parts = re.match(r'^/(.+)/([ismxAEGRBUIPHDMCKYOS]*)$', pcre_str)
            if pcre_parts:
                pattern = pcre_parts.group(1)
                modifiers = pcre_parts.group(2)

                pcre = PCREMatch(
                    pattern=pattern,
                    modifiers=modifiers,
                    relative='R' in modifiers,
                    http_uri='U' in modifiers,
                    http_request_body='P' in modifiers,
                    http_header='H' in modifiers,
                    http_method='M' in modifiers,
                )
                pcres.append(pcre)

        return pcres

    def _parse_flow(self, flow_str: str) -> FlowOptions:
        """解析 flow 选项"""
        flow_str = flow_str.lower()
        return FlowOptions(
            established='established' in flow_str,
            not_established='not_established' in flow_str,
            stateless='stateless' in flow_str,
            to_server='to_server' in flow_str,
            to_client='to_client' in flow_str,
            from_server='from_server' in flow_str,
            from_client='from_client' in flow_str,
        )

    def _tokenize_options(self, options_str: str) -> List[str]:
        """将选项字符串分割为 token 列表"""
        tokens = []
        current = ""
        in_quotes = False
        depth = 0

        for char in options_str:
            if char == '"' and (not current or current[-1] != '\\'):
                in_quotes = not in_quotes
                current += char
            elif char == '(' and not in_quotes:
                depth += 1
                current += char
            elif char == ')' and not in_quotes:
                depth -= 1
                current += char
            elif char == ';' and not in_quotes and depth == 0:
                if current.strip():
                    tokens.append(current.strip())
                current = ""
            else:
                current += char

        if current.strip():
            tokens.append(current.strip())

        return tokens

    def _unescape_content(self, content: str) -> bytes:
        """处理 content 中的转义序列"""
        result = bytearray()
        i = 0

        while i < len(content):
            # 十六进制模式 |XX XX|
            if content[i] == '|':
                end = content.find('|', i + 1)
                if end != -1:
                    hex_str = content[i+1:end].replace(' ', '')
                    try:
                        result.extend(bytes.fromhex(hex_str))
                    except ValueError:
                        pass
                    i = end + 1
                    continue

            # 转义字符
            if content[i] == '\\' and i + 1 < len(content):
                next_char = content[i + 1]
                escape_map = {
                    'n': b'\n',
                    'r': b'\r',
                    't': b'\t',
                    '\\': b'\\',
                    '"': b'"',
                    ';': b';',
                    ':': b':',
                }
                if next_char in escape_map:
                    result.extend(escape_map[next_char])
                    i += 2
                    continue
                # \xHH 形式
                if next_char == 'x' and i + 3 < len(content):
                    try:
                        result.append(int(content[i+2:i+4], 16))
                        i += 4
                        continue
                    except ValueError:
                        pass

            result.append(ord(content[i]))
            i += 1

        return bytes(result)

    def _check_auto_generate(self, rule: ParsedRule):
        """检查规则是否可以自动生成测试流量"""
        unsupported = []

        # 检查不支持的关键字
        unsupported_keywords = [
            ('flowbits', '需要多规则状态关联'),
            ('xbits', '需要跨流状态'),
            ('threshold', '需要多次触发'),
            ('detection_filter', '需要多次触发'),
            ('tag', '需要会话标记'),
            ('tls.', '加密流量无法模拟'),
            ('ja3', '需要真实 TLS 握手'),
            ('ssh.', '加密流量无法模拟'),
            ('filemagic', '需要真实文件'),
            ('filemd5', '需要真实文件'),
            ('filesha', '需要真实文件'),
        ]

        for keyword, reason in unsupported_keywords:
            if keyword in rule.raw_rule.lower():
                unsupported.append(f"{keyword}: {reason}")

        if unsupported:
            rule.can_auto_generate = False
            rule.unsupported_reason = "; ".join(unsupported)
```

### 3.2 PCRE 反向生成器

```python
"""
pcre_reverser.py - 从 PCRE 正则表达式生成匹配字符串
"""

import re
import random
import string
from typing import Optional, List

# 使用 exrex 库进行正则反向生成
try:
    import exrex
    HAS_EXREX = True
except ImportError:
    HAS_EXREX = False

try:
    import rstr
    HAS_RSTR = True
except ImportError:
    HAS_RSTR = False


class PCREReverser:
    """PCRE 正则表达式反向生成器"""

    # 常见攻击模式的预设样本
    PATTERN_SAMPLES = {
        # SQL 注入
        r'union.*select': "union all select",
        r'or\s+1\s*=\s*1': "or 1=1",
        r"'\s*or\s*'": "' or '",
        r';\s*drop\s+table': "; drop table",
        r'exec\s*\(': "exec(",

        # XSS
        r'<script': "<script>",
        r'javascript:': "javascript:",
        r'on\w+\s*=': "onclick=",
        r'<img[^>]+onerror': '<img src=x onerror=',

        # 路径遍历
        r'\.\.\/': "../",
        r'\.\.\\': "..\\",
        r'%2e%2e': "%2e%2e%2f",

        # 命令注入
        r';\s*\w+': "; ls",
        r'\|\s*\w+': "| cat",
        r'`[^`]+`': "`id`",
        r'\$\([^)]+\)': "$(whoami)",

        # 常见恶意 UA
        r'wget|curl': "wget",
        r'nikto|sqlmap': "sqlmap",
        r'nmap|masscan': "nmap",

        # 文件扩展名
        r'\.(php|asp|jsp)': ".php",
        r'\.(exe|dll|bat)': ".exe",
        r'\.(sh|bash|ps1)': ".sh",
    }

    def __init__(self):
        self.max_length = 100  # 生成字符串的最大长度
        self.max_count = 10    # 无限匹配的最大重复次数

    def generate(self, pattern: str, modifiers: str = "") -> Optional[str]:
        """
        从 PCRE 模式生成匹配字符串

        Args:
            pattern: PCRE 正则表达式（不含分隔符）
            modifiers: 修饰符字符串

        Returns:
            匹配的字符串，失败返回 None
        """
        # 1. 首先检查预设样本
        sample = self._check_preset_samples(pattern)
        if sample:
            return sample

        # 2. 清理和简化 PCRE 模式
        simplified = self._simplify_pattern(pattern, modifiers)

        # 3. 尝试使用 exrex 生成
        if HAS_EXREX:
            try:
                result = exrex.getone(simplified, limit=self.max_count)
                if result and len(result) <= self.max_length:
                    return result
            except Exception:
                pass

        # 4. 尝试使用 rstr 生成
        if HAS_RSTR:
            try:
                result = rstr.xeger(simplified)
                if result and len(result) <= self.max_length:
                    return result
            except Exception:
                pass

        # 5. 尝试手动解析简单模式
        manual = self._manual_generate(pattern)
        if manual:
            return manual

        return None

    def _check_preset_samples(self, pattern: str) -> Optional[str]:
        """检查是否匹配预设样本"""
        pattern_lower = pattern.lower()

        for preset_pattern, sample in self.PATTERN_SAMPLES.items():
            try:
                if re.search(preset_pattern, sample, re.IGNORECASE):
                    # 验证样本确实匹配原始 pattern
                    if re.search(pattern, sample, re.IGNORECASE):
                        return sample
            except re.error:
                continue

        return None

    def _simplify_pattern(self, pattern: str, modifiers: str = "") -> str:
        """简化 PCRE 模式，使其更容易被 exrex 处理"""
        simplified = pattern

        # 移除不支持的 PCRE 特性
        # (?:...) 非捕获组 -> 普通组
        simplified = re.sub(r'\(\?:', '(', simplified)

        # (?i) 等内联修饰符 -> 移除
        simplified = re.sub(r'\(\?[imsx]+\)', '', simplified)

        # (?=...) 前向断言 -> 移除（无法反向生成）
        simplified = re.sub(r'\(\?=[^)]+\)', '', simplified)

        # (?!...) 负前向断言 -> 移除
        simplified = re.sub(r'\(\?![^)]+\)', '', simplified)

        # (?<=...) 后向断言 -> 移除
        simplified = re.sub(r'\(\?<=[^)]+\)', '', simplified)

        # (?<!...) 负后向断言 -> 移除
        simplified = re.sub(r'\(\?<![^)]+\)', '', simplified)

        # 限制无限量词
        # .* -> .{0,10}
        simplified = re.sub(r'\.\*', '.{0,10}', simplified)
        # .+ -> .{1,10}
        simplified = re.sub(r'\.\+', '.{1,10}', simplified)
        # \s* -> \s{0,5}
        simplified = re.sub(r'\\s\*', r'\\s{0,5}', simplified)
        # \w+ -> \w{1,10}
        simplified = re.sub(r'\\w\+', r'\\w{1,10}', simplified)

        # 移除行锚点
        simplified = simplified.lstrip('^').rstrip('$')

        return simplified

    def _manual_generate(self, pattern: str) -> Optional[str]:
        """手动解析简单模式生成字符串"""
        result = []
        i = 0

        while i < len(pattern):
            char = pattern[i]

            # 字面量字符
            if char == '\\' and i + 1 < len(pattern):
                next_char = pattern[i + 1]
                escape_map = {
                    'd': random.choice('0123456789'),
                    'w': random.choice(string.ascii_letters + string.digits + '_'),
                    's': ' ',
                    'n': '\n',
                    'r': '\r',
                    't': '\t',
                }
                if next_char in escape_map:
                    result.append(escape_map[next_char])
                else:
                    result.append(next_char)
                i += 2
                continue

            # 字符类 [...]
            if char == '[':
                end = pattern.find(']', i)
                if end != -1:
                    char_class = pattern[i+1:end]
                    # 简单处理：取第一个字符或范围的第一个
                    if char_class.startswith('^'):
                        # 排除类，随机选一个不在其中的
                        result.append('X')
                    elif '-' in char_class and len(char_class) >= 3:
                        # 范围，取起始字符
                        result.append(char_class[0])
                    else:
                        result.append(char_class[0])
                    i = end + 1
                    continue

            # 点号
            if char == '.':
                result.append(random.choice(string.ascii_letters))
                i += 1
                continue

            # 量词
            if char in '*+?':
                # 对最后一个字符应用量词
                if char == '*':
                    pass  # 0 次，不添加
                elif char == '+':
                    if result:
                        result.append(result[-1])  # 至少 1 次
                # ? 不需要处理
                i += 1
                continue

            # 分组
            if char == '(':
                # 跳过分组，简单处理
                depth = 1
                j = i + 1
                while j < len(pattern) and depth > 0:
                    if pattern[j] == '(':
                        depth += 1
                    elif pattern[j] == ')':
                        depth -= 1
                    j += 1
                i = j
                continue

            # 选择
            if char == '|':
                # 已有内容，停止
                if result:
                    break
                i += 1
                continue

            # 普通字符
            if char not in '^$':
                result.append(char)
            i += 1

        if result:
            return ''.join(result)
        return None

    def generate_variants(self, pattern: str, count: int = 5) -> List[str]:
        """生成多个不同的匹配字符串变体"""
        variants = set()

        for _ in range(count * 3):  # 多尝试几次以获得足够的变体
            variant = self.generate(pattern)
            if variant:
                variants.add(variant)
            if len(variants) >= count:
                break

        return list(variants)
```

### 3.3 流量构建器

```python
"""
traffic_builder.py - 根据解析的规则构建测试流量
"""

from scapy.all import *
from typing import List, Optional, Tuple
from dataclasses import dataclass
import random

from rule_parser import ParsedRule, Protocol, ContentMatch, PCREMatch, FlowOptions
from pcre_reverser import PCREReverser


@dataclass
class GeneratedTraffic:
    """生成的测试流量"""
    packets: List[Packet]                 # 数据包列表
    description: str                      # 描述
    expected_to_trigger: bool             # 预期是否触发
    rule_sid: int                         # 对应规则 SID
    protocol: str                         # 协议
    payload_preview: str                  # payload 预览


class TrafficBuilder:
    """测试流量构建器"""

    def __init__(self, target_ip: str = "192.168.1.100",
                 target_port: int = 80,
                 source_ip: str = "10.0.0.50",
                 interface: str = "eth0"):
        self.target_ip = target_ip
        self.target_port = target_port
        self.source_ip = source_ip
        self.interface = interface
        self.pcre_reverser = PCREReverser()

        # TCP 序列号追踪
        self.seq = 1000
        self.ack = 1

    def build(self, rule: ParsedRule) -> Optional[GeneratedTraffic]:
        """根据规则构建测试流量"""
        if not rule.can_auto_generate:
            return None

        # 确定目标端口
        target_port = self._resolve_port(rule.dst_port)

        # 根据协议选择构建器
        if rule.protocol == Protocol.HTTP or self._is_http_rule(rule):
            return self._build_http(rule, target_port)
        elif rule.protocol == Protocol.DNS:
            return self._build_dns(rule)
        elif rule.protocol == Protocol.TCP:
            return self._build_tcp(rule, target_port)
        elif rule.protocol == Protocol.UDP:
            return self._build_udp(rule, target_port)
        elif rule.protocol == Protocol.ICMP:
            return self._build_icmp(rule)
        else:
            return self._build_tcp(rule, target_port)

    def _is_http_rule(self, rule: ParsedRule) -> bool:
        """判断是否为 HTTP 规则"""
        # 检查 content 是否绑定到 HTTP 缓冲区
        for content in rule.contents:
            if any([content.http_method, content.http_uri, content.http_header,
                   content.http_user_agent, content.http_host,
                   content.http_request_body, content.http_response_body]):
                return True

        # 检查 PCRE 修饰符
        for pcre in rule.pcres:
            if any([pcre.http_uri, pcre.http_header, pcre.http_method]):
                return True

        # 检查端口
        if rule.dst_port in ['80', '8080', '443', '$HTTP_PORTS']:
            return True

        return False

    def _build_http(self, rule: ParsedRule, port: int) -> GeneratedTraffic:
        """构建 HTTP 测试流量"""
        packets = []

        # 初始化 HTTP 请求组件
        method = "GET"
        uri = "/"
        headers = {
            "Host": self.target_ip,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Test-Traffic-Generator",
            "Accept": "*/*",
            "Connection": "close",
        }
        body = b""

        # 从 contents 提取 HTTP 组件
        general_contents = []  # 未绑定到特定缓冲区的 content

        for content in rule.contents:
            value = content.value
            value_str = value.decode('utf-8', errors='replace')

            if content.http_method:
                method = value_str.strip()
            elif content.http_uri or content.http_raw_uri:
                # URI 可能只是部分匹配
                if not uri.endswith(value_str) and value_str not in uri:
                    if value_str.startswith('/'):
                        uri = value_str
                    else:
                        uri = '/' + value_str
            elif content.http_user_agent:
                headers["User-Agent"] = value_str
            elif content.http_host:
                headers["Host"] = value_str
            elif content.http_header:
                # 尝试解析为 header: value 格式
                if b':' in value:
                    h_name, h_value = value.split(b':', 1)
                    headers[h_name.decode().strip()] = h_value.decode().strip()
                else:
                    # 添加为自定义 header
                    headers[f"X-Match-{len(headers)}"] = value_str
            elif content.http_cookie:
                headers["Cookie"] = value_str
            elif content.http_content_type:
                headers["Content-Type"] = value_str
            elif content.http_request_body:
                body += value
            else:
                # 通用 content，稍后处理
                general_contents.append(content)

        # 处理 PCRE
        for pcre in rule.pcres:
            generated = self.pcre_reverser.generate(pcre.pattern, pcre.modifiers)
            if generated:
                if pcre.http_uri:
                    if not generated.startswith('/'):
                        generated = '/' + generated
                    uri = generated
                elif pcre.http_method:
                    method = generated
                elif pcre.http_header:
                    headers[f"X-PCRE-{len(headers)}"] = generated
                elif pcre.http_request_body:
                    body += generated.encode()
                else:
                    # 默认放在 URI 或 header
                    if '/' in generated or '?' in generated:
                        uri = generated if generated.startswith('/') else '/' + generated
                    else:
                        headers[f"X-Pattern-{len(headers)}"] = generated

        # 处理未绑定的 content
        for content in general_contents:
            value_str = content.value.decode('utf-8', errors='replace')

            # 根据内容特征猜测放置位置
            if value_str.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']:
                method = value_str.upper()
            elif value_str.startswith('/') or '=' in value_str or '?' in value_str:
                # 看起来像 URI
                if value_str.startswith('/'):
                    uri = value_str
                else:
                    uri = '/' + value_str
            else:
                # 放在自定义 header 中确保匹配
                headers[f"X-Content-{len(headers)}"] = value_str

        # 处理 body 的情况
        if body or method in ['POST', 'PUT']:
            if not body:
                body = b"data=test"
            headers["Content-Length"] = str(len(body))
            if "Content-Type" not in headers:
                headers["Content-Type"] = "application/x-www-form-urlencoded"

        # 处理 urilen 约束
        if rule.urilen:
            uri = self._adjust_uri_length(uri, rule.urilen)

        # 构建 HTTP 请求
        http_request = f"{method} {uri} HTTP/1.1\r\n"
        for h_name, h_value in headers.items():
            http_request += f"{h_name}: {h_value}\r\n"
        http_request += "\r\n"

        http_payload = http_request.encode() + body

        # 是否需要 TCP 握手
        if rule.flow and rule.flow.established:
            packets = self._create_tcp_session(port, http_payload)
        else:
            pkt = (IP(src=self.source_ip, dst=self.target_ip) /
                   TCP(sport=random.randint(1024, 65535), dport=port, flags='PA') /
                   Raw(load=http_payload))
            packets = [pkt]

        return GeneratedTraffic(
            packets=packets,
            description=f"HTTP {method} {uri[:50]}...",
            expected_to_trigger=True,
            rule_sid=rule.sid,
            protocol="HTTP",
            payload_preview=http_request[:200]
        )

    def _build_tcp(self, rule: ParsedRule, port: int) -> GeneratedTraffic:
        """构建 TCP 测试流量"""
        packets = []

        # 构建 payload
        payload = self._build_payload_from_contents(rule.contents, rule.pcres)

        # 处理 dsize 约束
        if rule.dsize:
            payload = self._adjust_payload_size(payload, rule.dsize)

        # 处理 TCP flags
        tcp_flags = 'PA'  # 默认 PSH+ACK
        if rule.flags:
            tcp_flags = self._parse_tcp_flags(rule.flags)

        # 是否需要 TCP 握手
        if rule.flow and rule.flow.established:
            packets = self._create_tcp_session(port, payload, tcp_flags)
        else:
            pkt = (IP(src=self.source_ip, dst=self.target_ip) /
                   TCP(sport=random.randint(1024, 65535), dport=port, flags=tcp_flags) /
                   Raw(load=payload))
            packets = [pkt]

        return GeneratedTraffic(
            packets=packets,
            description=f"TCP to port {port}, {len(payload)} bytes",
            expected_to_trigger=True,
            rule_sid=rule.sid,
            protocol="TCP",
            payload_preview=payload[:100].hex() if payload else ""
        )

    def _build_udp(self, rule: ParsedRule, port: int) -> GeneratedTraffic:
        """构建 UDP 测试流量"""
        payload = self._build_payload_from_contents(rule.contents, rule.pcres)

        if rule.dsize:
            payload = self._adjust_payload_size(payload, rule.dsize)

        pkt = (IP(src=self.source_ip, dst=self.target_ip) /
               UDP(sport=random.randint(1024, 65535), dport=port) /
               Raw(load=payload))

        return GeneratedTraffic(
            packets=[pkt],
            description=f"UDP to port {port}, {len(payload)} bytes",
            expected_to_trigger=True,
            rule_sid=rule.sid,
            protocol="UDP",
            payload_preview=payload[:100].hex() if payload else ""
        )

    def _build_dns(self, rule: ParsedRule) -> GeneratedTraffic:
        """构建 DNS 测试流量"""
        qname = "example.com"

        # 从 content 提取查询域名
        for content in rule.contents:
            if content.dns_query:
                qname = content.value.decode('utf-8', errors='replace')
                # DNS 域名可能包含长度前缀，清理
                qname = qname.replace('\x00', '.').strip('.')
                break
            else:
                # 普通 content 也可能是域名
                value_str = content.value.decode('utf-8', errors='replace')
                if '.' in value_str and not value_str.startswith('/'):
                    qname = value_str

        # 从 PCRE 生成域名
        for pcre in rule.pcres:
            generated = self.pcre_reverser.generate(pcre.pattern)
            if generated and '.' in generated:
                qname = generated
                break

        pkt = (IP(src=self.source_ip, dst=self.target_ip) /
               UDP(sport=random.randint(1024, 65535), dport=53) /
               DNS(rd=1, qd=DNSQR(qname=qname)))

        return GeneratedTraffic(
            packets=[pkt],
            description=f"DNS query for {qname}",
            expected_to_trigger=True,
            rule_sid=rule.sid,
            protocol="DNS",
            payload_preview=f"Query: {qname}"
        )

    def _build_icmp(self, rule: ParsedRule) -> GeneratedTraffic:
        """构建 ICMP 测试流量"""
        icmp_type = rule.itype if rule.itype is not None else 8  # 默认 echo request
        icmp_code = rule.icode if rule.icode is not None else 0

        payload = self._build_payload_from_contents(rule.contents, rule.pcres)

        pkt = (IP(src=self.source_ip, dst=self.target_ip) /
               ICMP(type=icmp_type, code=icmp_code) /
               Raw(load=payload))

        return GeneratedTraffic(
            packets=[pkt],
            description=f"ICMP type={icmp_type} code={icmp_code}",
            expected_to_trigger=True,
            rule_sid=rule.sid,
            protocol="ICMP",
            payload_preview=payload[:50].hex() if payload else ""
        )

    def _build_payload_from_contents(self, contents: List[ContentMatch],
                                      pcres: List[PCREMatch]) -> bytes:
        """从 content 和 pcre 构建 payload"""
        parts = []

        for content in contents:
            # 考虑位置约束
            if content.offset:
                # 在指定偏移处插入
                while len(b''.join(parts)) < content.offset:
                    parts.append(b'X')  # 填充

            if content.distance and parts:
                # 与上一个 content 保持距离
                parts.append(b'X' * content.distance)

            parts.append(content.value)

        # 添加 PCRE 生成的内容
        for pcre in pcres:
            generated = self.pcre_reverser.generate(pcre.pattern, pcre.modifiers)
            if generated:
                parts.append(generated.encode())

        return b''.join(parts)

    def _create_tcp_session(self, port: int, payload: bytes,
                            flags: str = 'PA') -> List[Packet]:
        """创建完整的 TCP 会话（三次握手 + 数据）"""
        packets = []
        sport = random.randint(1024, 65535)

        # SYN
        syn = (IP(src=self.source_ip, dst=self.target_ip) /
               TCP(sport=sport, dport=port, flags='S', seq=self.seq))
        packets.append(syn)

        # SYN-ACK (模拟响应)
        syn_ack = (IP(src=self.target_ip, dst=self.source_ip) /
                   TCP(sport=port, dport=sport, flags='SA',
                       seq=0, ack=self.seq + 1))
        packets.append(syn_ack)

        # ACK
        ack = (IP(src=self.source_ip, dst=self.target_ip) /
               TCP(sport=sport, dport=port, flags='A',
                   seq=self.seq + 1, ack=1))
        packets.append(ack)

        # 数据包
        if payload:
            data_pkt = (IP(src=self.source_ip, dst=self.target_ip) /
                        TCP(sport=sport, dport=port, flags=flags,
                            seq=self.seq + 1, ack=1) /
                        Raw(load=payload))
            packets.append(data_pkt)

        return packets

    def _resolve_port(self, port_str: str) -> int:
        """解析端口字符串"""
        port_map = {
            '$HTTP_PORTS': 80,
            '$HTTPS_PORTS': 443,
            '$DNS_PORTS': 53,
            '$SSH_PORTS': 22,
            '$FTP_PORTS': 21,
            '$SMTP_PORTS': 25,
            'any': 80,
        }

        if port_str in port_map:
            return port_map[port_str]

        try:
            return int(port_str)
        except ValueError:
            return self.target_port

    def _parse_tcp_flags(self, flags_str: str) -> str:
        """解析 TCP flags 字符串"""
        # Suricata flags: S, A, F, R, P, U, C, E
        # Scapy flags: F, S, R, P, A, U, E, C
        flag_map = {
            'S': 'S',  # SYN
            'A': 'A',  # ACK
            'F': 'F',  # FIN
            'R': 'R',  # RST
            'P': 'P',  # PSH
            'U': 'U',  # URG
            'C': 'C',  # CWR
            'E': 'E',  # ECE
        }

        result = ''
        for char in flags_str.upper():
            if char in flag_map:
                result += flag_map[char]

        return result if result else 'PA'

    def _adjust_uri_length(self, uri: str, urilen: str) -> str:
        """根据 urilen 约束调整 URI 长度"""
        # 解析 urilen 约束
        # 格式: >N, <N, N, N<>M
        current_len = len(uri)

        if urilen.startswith('>'):
            min_len = int(urilen[1:].strip()) + 1
            if current_len < min_len:
                uri += 'X' * (min_len - current_len)
        elif urilen.startswith('<'):
            max_len = int(urilen[1:].strip()) - 1
            if current_len > max_len:
                uri = uri[:max_len]
        elif '<>' in urilen:
            parts = urilen.split('<>')
            min_len, max_len = int(parts[0]), int(parts[1])
            if current_len < min_len:
                uri += 'X' * (min_len - current_len)
            elif current_len > max_len:
                uri = uri[:max_len]

        return uri

    def _adjust_payload_size(self, payload: bytes, dsize: str) -> bytes:
        """根据 dsize 约束调整 payload 大小"""
        current_size = len(payload)

        if dsize.startswith('>'):
            min_size = int(dsize[1:].strip()) + 1
            if current_size < min_size:
                payload += b'X' * (min_size - current_size)
        elif dsize.startswith('<'):
            max_size = int(dsize[1:].strip()) - 1
            if current_size > max_size:
                payload = payload[:max_size]
        elif '<>' in dsize:
            parts = dsize.split('<>')
            min_size, max_size = int(parts[0]), int(parts[1])
            if current_size < min_size:
                payload += b'X' * (min_size - current_size)
            elif current_size > max_size:
                payload = payload[:max_size]

        return payload

    def save_pcap(self, traffic: GeneratedTraffic, filename: str):
        """保存流量到 PCAP 文件"""
        wrpcap(filename, traffic.packets)

    def send(self, traffic: GeneratedTraffic):
        """发送流量到网络"""
        for pkt in traffic.packets:
            sendp(Ether()/pkt, iface=self.interface, verbose=False)
```

### 3.4 测试引擎

```python
"""
test_engine.py - 规则测试引擎
"""

import os
import json
import time
import subprocess
from pathlib import Path
from typing import List, Optional, Dict
from dataclasses import dataclass, asdict

from rule_parser import SuricataRuleParser, ParsedRule
from traffic_builder import TrafficBuilder, GeneratedTraffic


@dataclass
class TestResult:
    """测试结果"""
    rule_sid: int
    rule_msg: str
    can_auto_generate: bool
    unsupported_reason: str
    test_executed: bool
    alert_triggered: bool
    alert_count: int
    execution_time_ms: float
    traffic_description: str
    error: Optional[str] = None


class RuleTestEngine:
    """规则测试引擎"""

    def __init__(self,
                 suricata_bin: str = "/usr/bin/suricata",
                 eve_log_path: str = "/var/log/suricata/eve.json",
                 rules_dir: str = "/var/lib/suricata/rules",
                 target_ip: str = "192.168.1.100",
                 target_port: int = 80,
                 test_interface: str = "lo"):
        self.suricata_bin = suricata_bin
        self.eve_log_path = eve_log_path
        self.rules_dir = rules_dir
        self.target_ip = target_ip
        self.target_port = target_port
        self.test_interface = test_interface

        self.parser = SuricataRuleParser()
        self.builder = TrafficBuilder(
            target_ip=target_ip,
            target_port=target_port,
            interface=test_interface
        )

    def test_rule(self, rule_text: str, timeout: float = 5.0) -> TestResult:
        """测试单条规则"""
        start_time = time.time()

        # 1. 解析规则
        try:
            parsed = self.parser.parse(rule_text)
        except Exception as e:
            return TestResult(
                rule_sid=0,
                rule_msg="",
                can_auto_generate=False,
                unsupported_reason=str(e),
                test_executed=False,
                alert_triggered=False,
                alert_count=0,
                execution_time_ms=0,
                traffic_description="",
                error=f"Parse error: {e}"
            )

        # 2. 检查是否可以自动生成
        if not parsed.can_auto_generate:
            return TestResult(
                rule_sid=parsed.sid,
                rule_msg=parsed.msg,
                can_auto_generate=False,
                unsupported_reason=parsed.unsupported_reason,
                test_executed=False,
                alert_triggered=False,
                alert_count=0,
                execution_time_ms=0,
                traffic_description="",
                error=None
            )

        # 3. 生成测试流量
        try:
            traffic = self.builder.build(parsed)
            if not traffic:
                return TestResult(
                    rule_sid=parsed.sid,
                    rule_msg=parsed.msg,
                    can_auto_generate=False,
                    unsupported_reason="Traffic builder returned None",
                    test_executed=False,
                    alert_triggered=False,
                    alert_count=0,
                    execution_time_ms=0,
                    traffic_description="",
                    error=None
                )
        except Exception as e:
            return TestResult(
                rule_sid=parsed.sid,
                rule_msg=parsed.msg,
                can_auto_generate=True,
                unsupported_reason="",
                test_executed=False,
                alert_triggered=False,
                alert_count=0,
                execution_time_ms=0,
                traffic_description="",
                error=f"Build error: {e}"
            )

        # 4. 保存临时 PCAP 和规则文件
        tmp_dir = Path("/tmp/suricata_test")
        tmp_dir.mkdir(exist_ok=True)

        pcap_file = tmp_dir / f"test_{parsed.sid}.pcap"
        rule_file = tmp_dir / f"test_{parsed.sid}.rules"
        log_dir = tmp_dir / f"logs_{parsed.sid}"
        log_dir.mkdir(exist_ok=True)

        self.builder.save_pcap(traffic, str(pcap_file))
        rule_file.write_text(rule_text)

        # 5. 运行 Suricata 离线模式
        eve_file = log_dir / "eve.json"
        try:
            cmd = [
                self.suricata_bin,
                "-r", str(pcap_file),
                "-S", str(rule_file),
                "-l", str(log_dir),
                "--set", "outputs.0.eve-log.enabled=yes",
                "--set", f"outputs.0.eve-log.filename={eve_file}",
                "-k", "none",  # 不验证校验和
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

        except subprocess.TimeoutExpired:
            return TestResult(
                rule_sid=parsed.sid,
                rule_msg=parsed.msg,
                can_auto_generate=True,
                unsupported_reason="",
                test_executed=True,
                alert_triggered=False,
                alert_count=0,
                execution_time_ms=(time.time() - start_time) * 1000,
                traffic_description=traffic.description,
                error="Suricata timeout"
            )
        except Exception as e:
            return TestResult(
                rule_sid=parsed.sid,
                rule_msg=parsed.msg,
                can_auto_generate=True,
                unsupported_reason="",
                test_executed=False,
                alert_triggered=False,
                alert_count=0,
                execution_time_ms=(time.time() - start_time) * 1000,
                traffic_description=traffic.description,
                error=f"Suricata error: {e}"
            )

        # 6. 检查告警
        alert_count = 0
        alert_triggered = False

        if eve_file.exists():
            with open(eve_file) as f:
                for line in f:
                    try:
                        event = json.loads(line)
                        if event.get("event_type") == "alert":
                            if event.get("alert", {}).get("signature_id") == parsed.sid:
                                alert_count += 1
                                alert_triggered = True
                    except json.JSONDecodeError:
                        continue

        # 7. 清理临时文件
        try:
            pcap_file.unlink()
            rule_file.unlink()
            for f in log_dir.iterdir():
                f.unlink()
            log_dir.rmdir()
        except:
            pass

        execution_time = (time.time() - start_time) * 1000

        return TestResult(
            rule_sid=parsed.sid,
            rule_msg=parsed.msg,
            can_auto_generate=True,
            unsupported_reason="",
            test_executed=True,
            alert_triggered=alert_triggered,
            alert_count=alert_count,
            execution_time_ms=execution_time,
            traffic_description=traffic.description,
            error=None
        )

    def test_rules_batch(self, rules: List[str]) -> List[TestResult]:
        """批量测试规则"""
        results = []
        for rule in rules:
            result = self.test_rule(rule)
            results.append(result)
        return results

    def test_rules_file(self, rules_file: str) -> List[TestResult]:
        """测试规则文件"""
        results = []

        with open(rules_file) as f:
            current_rule = ""
            for line in f:
                line = line.strip()

                # 跳过注释和空行
                if not line or line.startswith('#'):
                    continue

                # 处理多行规则
                current_rule += " " + line

                # 规则以 ) 结尾
                if line.endswith(')'):
                    result = self.test_rule(current_rule.strip())
                    results.append(result)
                    current_rule = ""

        return results

    def generate_report(self, results: List[TestResult]) -> Dict:
        """生成测试报告"""
        total = len(results)
        can_generate = sum(1 for r in results if r.can_auto_generate)
        executed = sum(1 for r in results if r.test_executed)
        triggered = sum(1 for r in results if r.alert_triggered)
        errors = sum(1 for r in results if r.error)

        return {
            "summary": {
                "total_rules": total,
                "can_auto_generate": can_generate,
                "cannot_generate": total - can_generate,
                "tests_executed": executed,
                "alerts_triggered": triggered,
                "trigger_rate": f"{triggered/executed*100:.1f}%" if executed else "N/A",
                "errors": errors,
            },
            "details": [asdict(r) for r in results],
            "unsupported_rules": [
                {"sid": r.rule_sid, "msg": r.rule_msg, "reason": r.unsupported_reason}
                for r in results if not r.can_auto_generate
            ],
            "failed_triggers": [
                {"sid": r.rule_sid, "msg": r.rule_msg, "traffic": r.traffic_description}
                for r in results if r.test_executed and not r.alert_triggered
            ]
        }
```

---

## 4. 规则关键字处理策略

### 4.1 content 关键字处理

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    content 关键字处理策略                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  关键字                 处理方式                     示例                    │
│  ───────────────────────────────────────────────────────────────────────   │
│                                                                             │
│  content:"xxx"         直接使用字节值               content:"GET" → b"GET"  │
│                                                                             │
│  content:"|XX XX|"     十六进制解码                 content:"|0d 0a|" → \r\n│
│                                                                             │
│  content:"xx"; nocase  生成时忽略大小写             任意大小写组合           │
│                                                                             │
│  offset:N              在 payload 位置 N 处放置     前面填充 N 字节          │
│                                                                             │
│  depth:N               限制搜索深度                 确保内容在前 N 字节      │
│                                                                             │
│  distance:N            与前一 content 距离          中间插入 N 字节填充      │
│                                                                             │
│  within:N              在前一 content 后 N 内       紧跟前一内容             │
│                                                                             │
│  http.uri              放入 HTTP URI                构造 GET /xxx           │
│                                                                             │
│  http.header           放入 HTTP Header             X-Custom: xxx           │
│                                                                             │
│  http.user_agent       放入 User-Agent              User-Agent: xxx         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4.2 pcre 关键字处理

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PCRE 处理策略                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  正则模式                  处理方式                  生成示例                │
│  ───────────────────────────────────────────────────────────────────────   │
│                                                                             │
│  字面量: /admin/          直接使用                   "admin"                │
│                                                                             │
│  字符类: /[a-z]+/         exrex 生成                 "abc"                  │
│                                                                             │
│  数字: /user\d{3}/        exrex 生成                 "user123"              │
│                                                                             │
│  选择: /(get|post)/i      随机选一个                 "GET" 或 "POST"        │
│                                                                             │
│  量词: /a{2,5}/           生成范围内长度             "aaa"                  │
│                                                                             │
│  预设模式: /union.*select/ 使用预设样本库            "union all select"     │
│                                                                             │
│  复杂断言: /(?=.*admin)/   降级处理/预设样本         根据上下文猜测         │
│                                                                             │
│  不支持: /(?P<name>...)/   标记为不可自动生成        返回 None              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4.3 flow 关键字处理

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    flow 关键字处理策略                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  选项                      处理方式                                          │
│  ───────────────────────────────────────────────────────────────────────   │
│                                                                             │
│  flow:established          生成完整 TCP 三次握手                             │
│                            SYN → SYN-ACK → ACK → DATA                       │
│                                                                             │
│  flow:to_server            数据包方向: client → server                       │
│                            src=client_ip, dst=server_ip                     │
│                                                                             │
│  flow:to_client            数据包方向: server → client                       │
│                            src=server_ip, dst=client_ip                     │
│                                                                             │
│  flow:stateless            不需要握手，直接发送数据包                         │
│                                                                             │
│  flow:no_stream            使用单独数据包，不组装流                          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. 使用示例

### 5.1 测试单条规则

```python
from rule_parser import SuricataRuleParser
from traffic_builder import TrafficBuilder
from test_engine import RuleTestEngine

# 方式 1: 仅生成流量
rule = '''
alert http any any -> any any (
    msg:"ET MALWARE Suspicious wget User-Agent";
    flow:established,to_server;
    content:"wget"; nocase;
    http.user_agent;
    sid:2024001; rev:1;
)
'''

builder = TrafficBuilder(target_ip="192.168.1.100")
parser = SuricataRuleParser()

parsed = parser.parse(rule)
traffic = builder.build(parsed)

print(f"Generated {len(traffic.packets)} packets")
print(f"Description: {traffic.description}")
print(f"Payload preview:\n{traffic.payload_preview}")

# 保存为 PCAP
builder.save_pcap(traffic, "test_wget.pcap")

# 方式 2: 完整测试（需要 Suricata）
engine = RuleTestEngine()
result = engine.test_rule(rule)

print(f"SID: {result.rule_sid}")
print(f"Can auto-generate: {result.can_auto_generate}")
print(f"Alert triggered: {result.alert_triggered}")
```

### 5.2 批量测试规则文件

```python
engine = RuleTestEngine()
results = engine.test_rules_file("/var/lib/suricata/rules/emerging-malware.rules")
report = engine.generate_report(results)

print(f"Total rules: {report['summary']['total_rules']}")
print(f"Can auto-generate: {report['summary']['can_auto_generate']}")
print(f"Trigger rate: {report['summary']['trigger_rate']}")

# 输出无法自动生成的规则
for rule in report['unsupported_rules'][:10]:
    print(f"  SID {rule['sid']}: {rule['reason']}")
```

---

## 6. 系统集成架构

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         完整系统集成架构                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│                           ┌──────────────┐                                  │
│                           │   Web 前端   │                                  │
│                           │              │                                  │
│                           └──────┬───────┘                                  │
│                                  │                                          │
│                                  ▼                                          │
│                           ┌──────────────┐                                  │
│                           │   REST API   │                                  │
│                           └──────┬───────┘                                  │
│                                  │                                          │
│          ┌───────────────────────┼───────────────────────┐                  │
│          ▼                       ▼                       ▼                  │
│   ┌─────────────┐        ┌─────────────┐        ┌─────────────┐            │
│   │ Rule Parser │        │Traffic Build│        │Test Engine  │            │
│   │             │───────>│             │───────>│             │            │
│   │ 规则解析器  │        │ 流量构建器  │        │ 测试引擎    │            │
│   └─────────────┘        └──────┬──────┘        └──────┬──────┘            │
│          │                      │                      │                    │
│          │               ┌──────┴──────┐               │                    │
│          │               ▼             ▼               │                    │
│          │        ┌───────────┐ ┌───────────┐         │                    │
│          │        │PCRE Reverse│ │Protocol   │         │                    │
│          │        │(exrex)    │ │Handlers   │         │                    │
│          │        └───────────┘ └───────────┘         │                    │
│          │                                             │                    │
│          ▼                                             ▼                    │
│   ┌─────────────┐                               ┌─────────────┐            │
│   │Rule Database│                               │  Suricata   │            │
│   │ (PostgreSQL)│                               │  (离线模式) │            │
│   └─────────────┘                               └──────┬──────┘            │
│                                                        │                    │
│                                                        ▼                    │
│                                                 ┌─────────────┐            │
│                                                 │  EVE JSON   │            │
│                                                 │   告警日志  │            │
│                                                 └──────┬──────┘            │
│                                                        │                    │
│                                                        ▼                    │
│                                                 ┌─────────────┐            │
│                                                 │Test Results │            │
│                                                 │  测试结果   │            │
│                                                 └─────────────┘            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 7. 总结

### 7.1 能力覆盖

| 规则类型 | 覆盖率 | 处理方式 |
|----------|--------|----------|
| 纯 content 规则 | 98% | 直接提取并构造 |
| content + HTTP 缓冲区 | 95% | 映射到 HTTP 请求对应字段 |
| 简单 PCRE | 85% | exrex 反向生成 |
| 复杂 PCRE | 60% | 预设样本库 + 降级处理 |
| flow:established | 100% | 生成完整 TCP 握手 |
| dsize/urilen | 100% | 自动调整 payload 大小 |
| flowbits/多包检测 | 0% | 标记为不支持 |
| TLS/加密规则 | 0% | 标记为不支持 |

### 7.2 关键依赖

```bash
pip install scapy exrex rstr
```

### 7.3 核心优势

1. **无需 LLM**：纯算法实现，无 API 调用成本
2. **确定性生成**：相同规则总是生成相同流量
3. **可离线运行**：不依赖外部服务
4. **高覆盖率**：约 75-80% 的规则可自动测试
