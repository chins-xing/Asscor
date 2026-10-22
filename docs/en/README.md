# ASSCOR Documentation

> The primary documentation language is **Chinese**; English versions are
> added incrementally. This index links both the English documents (under this
> directory) and the authoritative Chinese originals.
>
> **Authority order:** numeric prefixes are authoritative — in case of conflict
> `1-current/` wins; conclusions under `4-archive/` are void and are kept for
> historical reference only. See [../README.md](../README.md) for the full
> classification rules.

## English documents

| Document | Content |
|----------|---------|
| [1-current/whitepapers/engineering-whitepaper.md](1-current/whitepapers/engineering-whitepaper.md) | SSAM 2.0 engineering whitepaper — architecture & implementation |
| [1-current/guides/user-manual.md](1-current/guides/user-manual.md) | User manual — installation, configuration, CLI, deployment |
| [1-current/reference/ssam-interface-spec.md](1-current/reference/ssam-interface-spec.md) | SSAM V2.0 provider interface specification & integration guide |
| [1-current/whitepapers/srd-whitepaper.md](1-current/whitepapers/srd-whitepaper.md) | Systemic Risk Dynamics (SRD) / Prism whitepaper — risk semantics, state evolution, collapse theory |
| [1-current/whitepapers/secure-mode-whitepaper.md](1-current/whitepapers/secure-mode-whitepaper.md) | Secure Mode whitepaper — default/run dual-mode config protection (this branch) |

## Chinese originals (authoritative)

### Whitepapers

| Document | Content |
|----------|---------|
| [../1-current/whitepapers/项目篇章-系统安全可接受性模型.md](../1-current/whitepapers/项目篇章-系统安全可接受性模型.md) | SSAM theoretical foundations and core concepts |
| [../1-current/whitepapers/工程实现白皮书.md](../1-current/whitepapers/工程实现白皮书.md) | ASSCOR engineering architecture and implementation |
| [../1-current/whitepapers/SPC安全态势计算模块技术白皮书.md](../1-current/whitepapers/SPC安全态势计算模块技术白皮书.md) | Security Posture Calculator — formulas and data sources |
| [../1-current/whitepapers/APT攻击分析与检测增强白皮书.md](../1-current/whitepapers/APT攻击分析与检测增强白皮书.md) | ATT&CK V19 integration and APT detection |
| [../1-current/guides/ASSCOR 使用手册.md](../1-current/guides/ASSCOR%20使用手册.md) | User manual — operations and configuration |
| [../1-current/whitepapers/ASSCOR 扩展体系白皮书.md](../1-current/whitepapers/ASSCOR%20扩展体系白皮书.md) | Plug-in / extension / adapter development guide |
| [../1-current/whitepapers/ASSCOR 扩展白皮书：内核安全域.md](../1-current/whitepapers/ASSCOR%20扩展白皮书：内核安全域.md) | The `kernel_security` domain design & implementation |
| [../1-current/reference/SSAM接口规范与接入指南.md](../1-current/reference/SSAM接口规范与接入指南.md) | SSAM Provider interfaces and integration guide |
| [../1-current/whitepapers/SSAM与SRD算法可移植性白皮书.md](../1-current/whitepapers/SSAM与SRD算法可移植性白皮书.md) | Algorithm portability across projects |
| [../1-current/whitepapers/Systemic Risk Dynamics（SRD）白皮书.md](../1-current/whitepapers/Systemic%20Risk%20Dynamics（SRD）白皮书.md) | Prism / SRD risk-propagation model |
| [../1-current/reference/等级保护检查项映射手册.md](../1-current/reference/等级保护检查项映射手册.md) | GB/T 22239-2019 graded-protection mapping |

### Audits

→ [../3-audits/](../3-audits/) — **the newest `*-verdict.md` prevails**; `archive/`
and `history/` are process records only.

| File | Content | Date |
|------|---------|------|
| [../3-audits/PROJECT_COMPLETION_AUDIT.md](../3-audits/PROJECT_COMPLETION_AUDIT.md) | Full project-completion review | 2026-06-18 |
| [../3-audits/ARCHITECTURE_DEEP_DIVE.md](../3-audits/ARCHITECTURE_DEEP_DIVE.md) | Deep architecture analysis (14 chapters) | 2026-06-05 |
| [../3-audits/SPC_MODULE_AUDIT.md](../3-audits/SPC_MODULE_AUDIT.md) | SPC module audit | 2026-05-27 |
| [../3-audits/ATTACK_MODULE_AUDIT.md](../3-audits/ATTACK_MODULE_AUDIT.md) | ATT&CK V19 module audit | 2026-05-27 |
| [../3-audits/history/](../3-audits/history/) | Historical fix reports (7) | 2026-05-27 ~ 06-01 |
| [../3-audits/archive/](../3-audits/archive/) | Superseded legacy audits (5) | 2026-05-26 ~ 06-03 |

### Architecture review

→ [../1-current/reference/asscor-architecture-review/](../1-current/reference/asscor-architecture-review/) — 20-chapter
English architecture review of the ASSCOR project (also available in Chinese
under `asscor-architecture-review-zh/`).

### Releases & plans (archived)

| File | Content |
|------|---------|
| [../4-archive/releases/RELEASE_v0.2.3.md](../4-archive/releases/RELEASE_v0.2.3.md) | v0.2.3 release notes |
| [../4-archive/releases/RELEASE_v0.2.2.md](../4-archive/releases/RELEASE_v0.2.2.md) | v0.2.2 release notes |
| [../1-current/reference/ROADMAP_v0.2.0_to_v1.0.0.md](../1-current/reference/ROADMAP_v0.2.0_to_v1.0.0.md) | Roadmap to 1.0.0 |
| [../4-archive/reviews/TECH_DEBT_OVERVIEW.md](../4-archive/reviews/TECH_DEBT_OVERVIEW.md) | Technical-debt overview (archived; superseded by `3-audits/TECHNICAL_DEBT_BACKLOG_2026-09-08.md`) |

## Project root

- [../../README_EN.md](../../README_EN.md) — project overview (English)
- [../../README.md](../../README.md) — project overview (Chinese)
