# SIEM-AEGIS: NCA ECC Security Operations Center, MITRE ATT&CK Correlation & DFIR Playbook Studio

**Lead Architect:** أ. طارق ابوعشي | Tareq Abuashi — Cybersecurity & Distributed Systems Architect  
**Target Alignment:** NCA & SITE Cybersecurity Program (`NCA ECC-2:2024`, `MITRE ATT&CK Enterprise v16`, `Sigma v2.0`, `NIST SP 800-61`)

---

## Executive Overview

**SIEM-AEGIS** is a real-time Security Operations Center (SOC), multi-source Sigma correlation engine, MITRE ATT&CK kill-chain visualizer, and Digital Forensics & Incident Response (DFIR) playbook workbench built in strict TypeScript and HTML5 Canvas 2D. It is purpose-built to demonstrate automated detection, containment, and National Cybersecurity Authority Essential Cybersecurity Controls (**NCA ECC**) compliance readiness.

---

## Core Architectural Modules

1. **Multi-Source SIEM & Sigma Correlation Engine (`src/engine/siemEngine.ts`)**
   - Normalizes live telemetry from **Windows Security Events (`4625`, `4688`, `4672`, `4769`)**, **Linux Auditd/Syslog**, **Zeek DNS/TLS JA3**, **EDR Process Trees**, and **Perimeter WAF**.
   - Computes real-time **EPS (Events/sec)**, **MTTD (Mean Time to Detect)**, **MTTR (Mean Time to Respond)**, and severity telemetry (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).

2. **Interactive 7-Tactic MITRE ATT&CK Enterprise Matrix**
   - Covers `Initial Access`, `Execution`, `Privilege Escalation`, `Credential Access`, `Lateral Movement`, `Command & Control`, and `Impact`.
   - Active attack injections illuminate matching techniques (`T1566.001`, `T1059.001`, `T1558.003`, `T1021.002`, `T1071.001`, `T1486`, `T1490`, etc.).
   - Clicking any technique opens its **Sigma YAML Detection Rule** and mapped **NCA ECC Control**.

3. **60fps Enterprise Kill-Chain Topology Canvas (`src/components/SocCanvas.ts`)**
   - Visualizes live traffic across `Perimeter WAF` ← `DMZ Mail/Web` ← `Active Directory DC-01` ← `Endpoint WS-14` ← `Core DB Vault`.
   - Renders **Lateral Movement Arcs**, **TLS JA3 C2 Beaconing pulses**, and the automated **SOAR Quarantine Ring** upon containment.

4. **NCA ECC 5-Domain Compliance Readiness Gauge**
   - Tracks live posture across all five NCA ECC domains:
     1. Cybersecurity Governance (حوكمة الأمن السيبراني)
     2. Cybersecurity Defense (تعزيز الأمن السيبراني)
     3. Cybersecurity Resilience (صمود الأمن السيبراني)
     4. Third-Party & Cloud Cybersecurity (الأطراف الخارجية والحوسبة السحابية)
     5. Industrial Control Systems ICS/OT (أنظمة التحكم الصناعي)
   - Dynamically degrades during active uncontained incidents and elevates to **98.6% Compliant** after full SOAR containment.

5. **Incident Injection, SOAR Playbook & NIST SP 800-61 DFIR Timeline**
   - Supports one-click adversary scenarios (Spear-Phishing & C2, Kerberoasting & SMB Lateral Movement, Ransomware Encryption & VSS Wipe) plus automated SOAR Host Isolation & Kerberos TGT Revocation.
   - Extracts live forensic **SHA-256 hashes**, C2 indicators, and process lineage across the 5-stage **NIST SP 800-61** lifecycle.

6. **Web Audio API Telemetry & NCA ECC Dossier Modal (`src/utils/audio.ts`)**
   - Synthesizes low-latency SOC telemetry ticks, attack alerts, and SOAR containment chimes with a live Mute toggle, paired with an interactive technical Dossier Modal.

---

## Local Build & Verification

```bash
npm run build
```

*Architected and engineered exclusively by **أ. طارق ابوعشي | Tareq Abuashi — Cybersecurity & Distributed Systems Architect**.*
