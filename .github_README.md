<div align="center">

# BOM-Tool

**MCP AI Agent 보안 분석 및 위험관리 플랫폼**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

---

## 📖 소개

BOM-Tool은 Model Context Protocol (MCP) 서버의 보안을 종합적으로 분석하고 관리하는 오픈소스 프로젝트입니다. 정적 코드 분석, 동적 분석, SBOM 생성, 취약점 분석 등 다양한 보안 도구를 통합하여 MCP 서버의 보안 위험을 사전에 탐지하고 관리할 수 있습니다.

## 🛠️ 주요 프로젝트

### 🛡️ [MCP-SAFER](https://github.com/BOM-Tool/MCP-SAFER)

MCP AI Agent 위험관리 점검 통합 플랫폼

- **DashBoard**: 웹 기반 통합 관리 대시보드
- **MCP-SCAN**: 정적 코드 분석 (SAST) 모듈
- **MCP-GateWay**: MCP 프록시 및 DLP 게이트웨이

### 📋 [SBOM-SCA](https://github.com/BOM-Tool/SBOM-SCA)

SBOM 생성 및 오픈소스 취약점 분석 도구

- CycloneDX 형식 SBOM 생성
- Go/npm 프로젝트 취약점 분석
- Call Graph 기반 Reachability Analysis

### ✅ [TOOL-VET](https://github.com/BOM-Tool/TOOL-VET)

MCP Tool 동적 검증 도구 (DAST)

- 동적 분석을 통한 MCP 특화 취약점 탐지
- MCP-01 ~ MCP-04 취약점 검증
- Sandbox 환경에서 안전한 분석

## 🔧 MCP-SAFER 주요 기능

| 모듈 | 기능 설명 |
|------|----------|
| 🖥️ **DashBoard** | 웹 기반 통합 관리 대시보드 - 모든 분석 결과를 한 곳에서 시각화 및 관리 |
| 🔍 **MCP-SCAN** | 정적 코드 분석 (SAST) - 소스 코드 실행 없이 취약점 탐지 및 MCP 특화 취약점 분석 |
| 📋 **SBOM-SCA** | SBOM 생성 및 오픈소스 취약점 분석 - CycloneDX 형식 SBOM 생성 및 의존성 취약점 탐지 |
| ✅ **TOOL-VET** | 동적 분석 (DAST) - 실제 실행 환경에서 MCP Tool 검증 및 취약점 탐지 |
| 🔐 **MCP-GateWay** | MCP 프록시 및 DLP - 실시간 트래픽 분석 및 민감정보 보호 |

## 🚀 빠른 시작

```bash
# MCP-SAFER 클론
git clone https://github.com/BOM-Tool/MCP-SAFER.git
cd MCP-SAFER

# Dashboard 실행
cd DashBoard
./start-all.sh
```

각 모듈은 독립적으로 사용할 수 있습니다. 자세한 사용법은 각 프로젝트의 README를 참고하세요.

## 📚 기술 스택

![React](https://img.shields.io/badge/React-19.1.1-blue.svg)
![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)
![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Go](https://img.shields.io/badge/Go-1.18+-00ADD8.svg)

## 📄 라이선스

이 프로젝트는 [MIT License](LICENSE)를 따릅니다.

---

<div align="center">

**Made with ❤️ by BOM-Tool**

[🌐 Website](#) • [📖 Documentation](#) • [🐛 Report Bug](#) • [💡 Request Feature](#)

</div>

