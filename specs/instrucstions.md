# Instruction

## explore

帮我研究一下市面上关于网络入侵检测的技术，尤其是suricata和snort的功能，探索它们实现的原理，保存到.specs/0001-explore-by-gemini.md

## deep learning explore

继续帮我探索，如何和深度学习集成：使用 CNN、LSTM、GAN 等算法提升检测能力，更新至文档中 

## suricata + et rules

基于suricata和Emerging Threats Open，实现入侵检测系统，要求如下：

1、设计前端，支持告警日志的查看和规则的管理。
2、支持定时和手动更新Emerging Threats Open规则、规则的版本管理。
3、针对每条规则，可以生成攻击流量（是否需要LLM介入），设计攻击测试工具（或者利用现有工具nmap、hping3、Scapy、tcpreplay等），将攻击流量打入suricata监听的网卡，suricata检测到攻击后，产生告警日志，告警日志支持前端展示，支持告警日志和对应规则关联。
4、 使用 mermaid 绘制架构，设计，组件，流程等图表并详细说明

帮我深度探索如上方案的可行性，保存到0002-suricata-explore.md


## design

基于./specs/0002-suricata-explore.md，进行详细的方案设计，要求如下：

1、


保存到./specs/0003-design.md