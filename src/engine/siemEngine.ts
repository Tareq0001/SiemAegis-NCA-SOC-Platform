/**
 * SIEM-AEGIS: Multi-Source Log Correlation, Sigma Engine, MITRE ATT&CK & NCA ECC Readiness Engine
 * Lead Architect: أ. طارق ابوعشي | Tareq Abuashi — Cybersecurity & Distributed Systems Architect
 */

export type SeverityLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type LogSource =
  | 'Windows Event'
  | 'Linux Auditd'
  | 'Zeek DNS/TLS'
  | 'EDR Process Tree'
  | 'Perimeter WAF';

export type MitreTacticId =
  | 'initial-access'
  | 'execution'
  | 'privilege-escalation'
  | 'credential-access'
  | 'lateral-movement'
  | 'command-and-control'
  | 'impact';

export type IncidentScenarioId = 'NONE' | 'PHISHING_C2' | 'KERBEROAST_SMB' | 'RANSOMWARE_WIPE';

export type DfirPhaseId = 'preparation' | 'detection' | 'containment' | 'eradication' | 'recovery';

export interface MitreTechnique {
  id: string;
  name: string;
  tacticId: MitreTacticId;
  tacticLabel: string;
  description: string;
  ncaControl: string;
  sigmaTitle: string;
  sigmaYaml: string;
  hits: number;
  active: boolean;
  contained: boolean;
}

export interface SiemLogEntry {
  id: number;
  timestamp: string;
  source: LogSource;
  eventId: string;
  host: string;
  srcIp: string;
  dstIp: string;
  severity: SeverityLevel;
  sigmaRule: string | null;
  mitreId: string | null;
  message: string;
}

export interface NcaDomainMetric {
  id: number;
  title: string;
  code: string;
  baselineScore: number;
  currentScore: number;
  controlsPassed: number;
  controlsTotal: number;
}

export interface DfirPhase {
  id: DfirPhaseId;
  label: string;
  status: 'COMPLETED' | 'ACTIVE' | 'PENDING';
  timestamp: string;
  summary: string;
}

export interface IocArtifact {
  type: 'SHA-256' | 'C2 IP / Domain' | 'Kerberos / Account' | 'Process Lineage';
  value: string;
  verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'QUARANTINED';
}

export interface SoarAuditEntry {
  id: number;
  timestamp: string;
  level: 'INFO' | 'WARN' | 'CRITICAL' | 'SOAR';
  message: string;
}

export interface SocSnapshot {
  running: boolean;
  speed: number;
  activeScenario: IncidentScenarioId;
  contained: boolean;
  eps: number;
  totalEvents: number;
  mttdSeconds: number;
  mttrSeconds: number;
  severityCounts: Record<SeverityLevel, number>;
  overallCompliance: number;
  complianceStatusLabel: string;
  ncaDomains: NcaDomainMetric[];
  mitreTechniques: MitreTechnique[];
  selectedTechniqueId: string;
  logs: SiemLogEntry[];
  dfirPhases: DfirPhase[];
  iocs: IocArtifact[];
  soarAudit: SoarAuditEntry[];
  isolatedHosts: string[];
  revokedTgtCount: number;
}

export const MITRE_TACTIC_COLUMNS: { id: MitreTacticId; label: string; shortCode: string }[] = [
  { id: 'initial-access', label: 'Initial Access', shortCode: 'TA0001' },
  { id: 'execution', label: 'Execution', shortCode: 'TA0002' },
  { id: 'privilege-escalation', label: 'Privilege Escalation', shortCode: 'TA0004' },
  { id: 'credential-access', label: 'Credential Access', shortCode: 'TA0006' },
  { id: 'lateral-movement', label: 'Lateral Movement', shortCode: 'TA0008' },
  { id: 'command-and-control', label: 'Command & Control', shortCode: 'TA0011' },
  { id: 'impact', label: 'Impact', shortCode: 'TA0040' },
];

function createInitialTechniques(): MitreTechnique[] {
  return [
    // Initial Access
    {
      id: 'T1566.001',
      name: 'Spearphishing Attachment',
      tacticId: 'initial-access',
      tacticLabel: 'Initial Access',
      description: 'Adversary delivers weaponized macro-enabled ISO/DOCM attachment via DMZ Mail Gateway.',
      ncaControl: 'ECC 2-7-3 (Email & Phishing Protection)',
      sigmaTitle: 'sigma_mail_macro_dropper.yml',
      sigmaYaml: `title: Weaponized Office Child Process Spawn\nid: aeg-1566-001\nlogsource: { product: windows, category: process_creation }\ndetection:\n  selection:\n    ParentImage|endswith: ['\\winword.exe', '\\outlook.exe']\n    Image|endswith: ['\\powershell.exe', '\\cmd.exe', '\\mshta.exe']\n  condition: selection\nlevel: high`,
      hits: 0,
      active: false,
      contained: false,
    },
    {
      id: 'T1190',
      name: 'Exploit Public-Facing App',
      tacticId: 'initial-access',
      tacticLabel: 'Initial Access',
      description: 'Probing DMZ reverse proxy / web API endpoints for deserialization and RCE payloads.',
      ncaControl: 'ECC 2-5-2 (Web Application Firewall)',
      sigmaTitle: 'sigma_waf_rce_probe.yml',
      sigmaYaml: `title: Perimeter WAF RCE / JNDI Injection Attempt\nid: aeg-1190-001\nlogsource: { category: webserver, product: waf }\ndetection:\n  selection:\n    cs-uri-query|contains: ['\${jndi:', '../etc/passwd', 'cmd.exe']\n  condition: selection\nlevel: medium`,
      hits: 1,
      active: false,
      contained: false,
    },
    // Execution
    {
      id: 'T1059.001',
      name: 'PowerShell Encoded Cmd',
      tacticId: 'execution',
      tacticLabel: 'Execution',
      description: 'Obfuscated Base64 PowerShell stage-2 loader executed in memory without touching disk.',
      ncaControl: 'ECC 2-4-3 (Endpoint Detection & Script Control)',
      sigmaTitle: 'sigma_posh_encoded_stager.yml',
      sigmaYaml: `title: Encoded PowerShell C2 Stager Execution\nid: aeg-1059-001\nlogsource: { product: windows, service: sysmon }\ndetection:\n  selection:\n    EventID: 4688\n    Image|endswith: '\\powershell.exe'\n    CommandLine|contains: ['-EncodedCommand', 'IEX(', 'Net.WebClient']\n  condition: selection\nlevel: critical`,
      hits: 0,
      active: false,
      contained: false,
    },
    {
      id: 'T1053.005',
      name: 'Scheduled Task Persistence',
      tacticId: 'execution',
      tacticLabel: 'Execution',
      description: 'Creation of hidden Windows Scheduled Task or Linux systemd timer for payload survival.',
      ncaControl: 'ECC 2-4-2 (Host Integrity Monitoring)',
      sigmaTitle: 'sigma_schtask_hidden.yml',
      sigmaYaml: `title: Suspicious Scheduled Task Creation\nid: aeg-1053-005\nlogsource: { product: windows, service: security }\ndetection:\n  selection:\n    EventID: 4698\n    TaskContent|contains: ['AppData\\Local\\Temp', 'powershell']\n  condition: selection\nlevel: high`,
      hits: 0,
      active: false,
      contained: false,
    },
    // Privilege Escalation
    {
      id: 'T1068',
      name: 'Exploitation for PrivEsc',
      tacticId: 'privilege-escalation',
      tacticLabel: 'Privilege Escalation',
      description: 'Abnormal SeDebugPrivilege / SeImpersonatePrivilege token assignment (Event ID 4672).',
      ncaControl: 'ECC 2-2-3 (Privileged Access Management)',
      sigmaTitle: 'sigma_special_priv_assign.yml',
      sigmaYaml: `title: Unexpected Special Privilege Assignment\nid: aeg-1068-001\nlogsource: { product: windows, service: security }\ndetection:\n  selection:\n    EventID: 4672\n    PrivilegeList|contains: ['SeDebugPrivilege', 'SeTcbPrivilege']\n  filter:\n    SubjectUserName|endswith: '$'\n  condition: selection and not filter\nlevel: high`,
      hits: 0,
      active: false,
      contained: false,
    },
    {
      id: 'T1548.003',
      name: 'Sudo & Auditd Escalation',
      tacticId: 'privilege-escalation',
      tacticLabel: 'Privilege Escalation',
      description: 'Linux auditd syscall trace detecting unauthorized sudoers / pkexec privilege elevation.',
      ncaControl: 'ECC 2-2-2 (Least Privilege Enforcement)',
      sigmaTitle: 'sigma_linux_auditd_privesc.yml',
      sigmaYaml: `title: Linux Auditd Root Escalation Anomaly\nid: aeg-1548-003\nlogsource: { product: linux, service: auditd }\ndetection:\n  selection:\n    type: 'EXECVE'\n    a0|contains: ['pkexec', 'sudoedit']\n    euid: 0\n  condition: selection\nlevel: high`,
      hits: 0,
      active: false,
      contained: false,
    },
    // Credential Access
    {
      id: 'T1558.003',
      name: 'Kerberoasting (RC4 TGS)',
      tacticId: 'credential-access',
      tacticLabel: 'Credential Access',
      description: 'Mass Kerberos TGS-REQ requests using weak RC4-HMAC (0x17) encryption against SPNs.',
      ncaControl: 'ECC 2-2-4 (Identity & Kerberos Hardening)',
      sigmaTitle: 'sigma_kerberoast_rc4_tgs.yml',
      sigmaYaml: `title: Kerberoasting RC4 Encryption Ticket Storm\nid: aeg-1558-003\nlogsource: { product: windows, service: security }\ndetection:\n  selection:\n    EventID: 4769\n    TicketEncryptionType: '0x17'\n    ServiceName|startswith: ['MSSQLSvc/', 'HTTP/']\n  timeframe: 1m\n  condition: selection | count() > 8\nlevel: critical`,
      hits: 0,
      active: false,
      contained: false,
    },
    {
      id: 'T1003.001',
      name: 'LSASS Memory Dump',
      tacticId: 'credential-access',
      tacticLabel: 'Credential Access',
      description: 'Process accessing lsass.exe with PROCESS_VM_READ to extract NTLM hashes and TGTs.',
      ncaControl: 'ECC 2-4-4 (Credential Guard & EDR)',
      sigmaTitle: 'sigma_edr_lsass_read.yml',
      sigmaYaml: `title: Unauthorized LSASS Memory Access\nid: aeg-1003-001\nlogsource: { product: windows, category: process_access }\ndetection:\n  selection:\n    TargetImage|endswith: '\\lsass.exe'\n    GrantedAccess|contains: ['0x1010', '0x1410', '0x1F0FFF']\n  condition: selection\nlevel: critical`,
      hits: 0,
      active: false,
      contained: false,
    },
    // Lateral Movement
    {
      id: 'T1021.002',
      name: 'SMB / Admin$ Lateral Move',
      tacticId: 'lateral-movement',
      tacticLabel: 'Lateral Movement',
      description: 'Lateral spread via SMB (445/TCP) Admin$ share from Endpoint WS-14 to DC-01 & Core DB.',
      ncaControl: 'ECC 2-5-3 (Micro-Segmentation & Lateral Control)',
      sigmaTitle: 'sigma_smb_lateral_admin_share.yml',
      sigmaYaml: `title: Remote SMB Admin$ Share Execution\nid: aeg-1021-002\nlogsource: { product: windows, service: security }\ndetection:\n  selection:\n    EventID: [5140, 4624]\n    ShareName: '\\\\*\\ADMIN$'\n    LogonType: 3\n  condition: selection\nlevel: critical`,
      hits: 0,
      active: false,
      contained: false,
    },
    {
      id: 'T1021.001',
      name: 'RDP Brute / Hijack',
      tacticId: 'lateral-movement',
      tacticLabel: 'Lateral Movement',
      description: 'Repeated Event ID 4625 failed logons followed by anomalous RDP session establishment.',
      ncaControl: 'ECC 2-2-1 (MFA & Remote Access Control)',
      sigmaTitle: 'sigma_4625_rdp_spray.yml',
      sigmaYaml: `title: RDP Password Spraying Event 4625\nid: aeg-1021-001\nlogsource: { product: windows, service: security }\ndetection:\n  selection:\n    EventID: 4625\n    LogonType: 10\n  timeframe: 30s\n  condition: selection | count() > 12\nlevel: high`,
      hits: 0,
      active: false,
      contained: false,
    },
    // Command & Control
    {
      id: 'T1071.001',
      name: 'HTTPS / TLS C2 Beaconing',
      tacticId: 'command-and-control',
      tacticLabel: 'Command & Control',
      description: 'Periodic jittered TLS 1.3 JA3 fingerprint beacons detected by Zeek DNS/TLS sensor.',
      ncaControl: 'ECC 2-5-4 (Egress Filtering & NDR)',
      sigmaTitle: 'sigma_zeek_ja3_c2_beacon.yml',
      sigmaYaml: `title: Zeek Anomalous JA3 TLS C2 Beacon\nid: aeg-1071-001\nlogsource: { product: zeek, service: ssl }\ndetection:\n  selection:\n    ja3: 'e7d705a3286e19ea42f587b344ee6865'\n    server_name|endswith: ['.top', '.xyz', 'cdn-sync-api.net']\n  condition: selection\nlevel: critical`,
      hits: 0,
      active: false,
      contained: false,
    },
    {
      id: 'T1105',
      name: 'Ingress Tool Transfer',
      tacticId: 'command-and-control',
      tacticLabel: 'Command & Control',
      description: 'Secondary ransomware / Mimikatz payload staged over encrypted channel into DMZ/WS-14.',
      ncaControl: 'ECC 2-4-1 (Malware & Payload Prevention)',
      sigmaTitle: 'sigma_ingress_payload_fetch.yml',
      sigmaYaml: `title: Suspicious Binary Ingress Transfer\nid: aeg-1105-001\nlogsource: { product: edr, category: network_connection }\ndetection:\n  selection:\n    Initiated: 'true'\n    DestinationPort: [443, 8443]\n    Image|endswith: ['\\certutil.exe', '\\curl.exe', '\\powershell.exe']\n  condition: selection\nlevel: high`,
      hits: 0,
      active: false,
      contained: false,
    },
    // Impact
    {
      id: 'T1486',
      name: 'Data Encrypted for Impact',
      tacticId: 'impact',
      tacticLabel: 'Impact',
      description: 'High-entropy ChaCha20/AES file rename burst targeting Core DB Vault & shared volumes.',
      ncaControl: 'ECC 3-1-2 (Cyber Resilience & Ransomware Defense)',
      sigmaTitle: 'sigma_edr_ransom_entropy_burst.yml',
      sigmaYaml: `title: High-Entropy Ransomware File Rename Burst\nid: aeg-1486-001\nlogsource: { product: edr, category: file_event }\ndetection:\n  selection:\n    TargetFilename|endswith: ['.aegis_enc', '.locked', '.crypt']\n  timeframe: 10s\n  condition: selection | count() > 25\nlevel: critical`,
      hits: 0,
      active: false,
      contained: false,
    },
    {
      id: 'T1490',
      name: 'Inhibit System Recovery',
      tacticId: 'impact',
      tacticLabel: 'Impact',
      description: 'Execution of vssadmin delete shadows / wbadmin / bcdedit to destroy recovery snapshots.',
      ncaControl: 'ECC 2-9-1 (Immutable Backup & Recovery Protection)',
      sigmaTitle: 'sigma_vssadmin_shadow_wipe.yml',
      sigmaYaml: `title: Volume Shadow Copy Deletion Attempt\nid: aeg-1490-001\nlogsource: { product: windows, category: process_creation }\ndetection:\n  selection:\n    EventID: 4688\n    Image|endswith: ['\\vssadmin.exe', '\\wmic.exe']\n    CommandLine|contains: ['delete shadows', 'shadowcopy delete']\n  condition: selection\nlevel: critical`,
      hits: 0,
      active: false,
      contained: false,
    },
  ];
}

function createInitialNcaDomains(): NcaDomainMetric[] {
  return [
    {
      id: 1,
      code: 'ECC-1',
      title: '1. Cybersecurity Governance (حوكمة الأمن السيبراني)',
      baselineScore: 98.2,
      currentScore: 98.2,
      controlsPassed: 29,
      controlsTotal: 30,
    },
    {
      id: 2,
      code: 'ECC-2',
      title: '2. Cybersecurity Defense (تعزيز الأمن السيبراني)',
      baselineScore: 96.8,
      currentScore: 96.8,
      controlsPassed: 54,
      controlsTotal: 56,
    },
    {
      id: 3,
      code: 'ECC-3',
      title: '3. Cybersecurity Resilience (صمود الأمن السيبراني)',
      baselineScore: 95.5,
      currentScore: 95.5,
      controlsPassed: 18,
      controlsTotal: 19,
    },
    {
      id: 4,
      code: 'ECC-4',
      title: '4. Third-Party & Cloud Cybersecurity (الأطراف الخارجية والحوسبة السحابية)',
      baselineScore: 96.0,
      currentScore: 96.0,
      controlsPassed: 14,
      controlsTotal: 15,
    },
    {
      id: 5,
      code: 'ECC-5',
      title: '5. Industrial Control Systems ICS/OT (أنظمة التحكم الصناعي)',
      baselineScore: 95.8,
      currentScore: 95.8,
      controlsPassed: 11,
      controlsTotal: 12,
    },
  ];
}

function formatUtcTime(date = new Date()): string {
  return date.toISOString().substring(11, 23);
}

export class SiemEngine {
  private running = true;
  private speed = 1;
  private activeScenario: IncidentScenarioId = 'NONE';
  private contained = false;

  private eps = 4820;
  private totalEvents = 184290;
  private mttdSeconds = 1.4;
  private mttrSeconds = 11.8;

  private severityCounts: Record<SeverityLevel, number> = {
    LOW: 142,
    MEDIUM: 24,
    HIGH: 3,
    CRITICAL: 0,
  };

  private ncaDomains: NcaDomainMetric[] = createInitialNcaDomains();
  private mitreTechniques: MitreTechnique[] = createInitialTechniques();
  private selectedTechniqueId = 'T1566.001';

  private logs: SiemLogEntry[] = [];
  private logSeq = 1000;
  private soarAudit: SoarAuditEntry[] = [];
  private auditSeq = 1;

  private dfirPhases: DfirPhase[] = [];
  private iocs: IocArtifact[] = [];
  private isolatedHosts: string[] = [];
  private revokedTgtCount = 0;

  private tickAccumulator = 0;

  constructor() {
    this.resetBaseline();
  }

  public isRunning(): boolean {
    return this.running;
  }

  public setRunning(state: boolean): void {
    this.running = state;
  }

  public setSpeed(speed: number): void {
    this.speed = speed;
  }

  public getSpeed(): number {
    return this.speed;
  }

  public selectTechnique(id: string): void {
    if (this.mitreTechniques.some((t) => t.id === id)) {
      this.selectedTechniqueId = id;
    }
  }

  public resetBaseline(): void {
    this.activeScenario = 'NONE';
    this.contained = false;
    this.eps = 4820;
    this.mttdSeconds = 1.4;
    this.mttrSeconds = 11.8;
    this.isolatedHosts = [];
    this.revokedTgtCount = 0;

    this.severityCounts = { LOW: 148, MEDIUM: 19, HIGH: 2, CRITICAL: 0 };
    this.ncaDomains = createInitialNcaDomains();
    this.mitreTechniques = createInitialTechniques();
    this.selectedTechniqueId = 'T1190';

    const now = formatUtcTime();
    this.dfirPhases = [
      {
        id: 'preparation',
        label: 'Preparation',
        status: 'ACTIVE',
        timestamp: now,
        summary: 'NCA ECC-2:2024 & Sigma v2.0 baseline telemetry active across 5 enterprise zones.',
      },
      {
        id: 'detection',
        label: 'Detection & Analysis',
        status: 'PENDING',
        timestamp: '--:--:--',
        summary: 'Awaiting high-confidence Sigma correlation chain.',
      },
      {
        id: 'containment',
        label: 'Containment',
        status: 'PENDING',
        timestamp: '--:--:--',
        summary: 'SOAR automated host isolation & Kerberos TGT revocation armed.',
      },
      {
        id: 'eradication',
        label: 'Eradication',
        status: 'PENDING',
        timestamp: '--:--:--',
        summary: 'Payload & persistence artifact purge standby.',
      },
      {
        id: 'recovery',
        label: 'Recovery',
        status: 'PENDING',
        timestamp: '--:--:--',
        summary: 'Zero-trust validation & NCA ECC compliance verification.',
      },
    ];

    this.iocs = [
      {
        type: 'SHA-256',
        value: '00000000000000000000000000000000 (Baseline Clean)',
        verdict: 'QUARANTINED',
      },
      {
        type: 'C2 IP / Domain',
        value: 'No active egress C2 beacons detected',
        verdict: 'QUARANTINED',
      },
      {
        type: 'Process Lineage',
        value: 'svchost.exe -> edr_sensor.exe (Signed NCA-SOC)',
        verdict: 'QUARANTINED',
      },
    ];

    this.logs = [];
    this.soarAudit = [];
    this.pushAudit('INFO', 'SIEM-AEGIS correlation engine initialized under NCA ECC-2:2024 baseline.');
    this.pushAudit('INFO', 'Subscribed to Windows Event (4625/4688/4672), Linux Auditd, Zeek TLS, EDR & Perimeter WAF.');

    for (let i = 0; i < 6; i++) {
      this.emitBaselineLog();
    }
  }

  public injectScenario(scenario: Exclude<IncidentScenarioId, 'NONE'>): void {
    this.activeScenario = scenario;
    this.contained = false;
    this.isolatedHosts = [];
    const now = formatUtcTime();

    if (scenario === 'PHISHING_C2') {
      this.activateTechniques(['T1566.001', 'T1059.001', 'T1071.001', 'T1105']);
      this.selectedTechniqueId = 'T1566.001';
      this.eps = 11420;
      this.mttdSeconds = 1.8;
      this.mttrSeconds = 42.0;

      this.applyDomainImpact([95.0, 68.4, 81.2, 74.5, 92.0]);

      this.iocs = [
        {
          type: 'SHA-256',
          value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          verdict: 'MALICIOUS',
        },
        {
          type: 'C2 IP / Domain',
          value: '185.220.101.47:443 (cdn-sync-api.net | JA3: e7d705a3...)',
          verdict: 'MALICIOUS',
        },
        {
          type: 'Kerberos / Account',
          value: 'ABHA\\f.alqahtani (Endpoint WS-14)',
          verdict: 'SUSPICIOUS',
        },
        {
          type: 'Process Lineage',
          value: 'outlook.exe -> winword.exe -> powershell.exe (-Enc)',
          verdict: 'MALICIOUS',
        },
      ];

      this.pushLog(
        'Perimeter WAF',
        'WAF-8841',
        'DMZ-Mail-01',
        '185.220.101.47',
        '10.10.2.14',
        'HIGH',
        'sigma_mail_macro_dropper.yml',
        'T1566.001',
        'Weaponized DOCM attachment Q3_Vendor_Invoice.docm bypassed SPF soft-fail on DMZ Mail.'
      );
      this.pushLog(
        'Windows Event',
        'Event ID 4688',
        'Endpoint WS-14',
        '10.20.4.14',
        '185.220.101.47',
        'CRITICAL',
        'sigma_posh_encoded_stager.yml',
        'T1059.001',
        'winword.exe spawned powershell.exe -NoP -W Hidden -EncodedCommand JABzAD0ATgBlAHcA...'
      );
      this.pushLog(
        'Zeek DNS/TLS',
        'SSL-JA3',
        'Endpoint WS-14',
        '10.20.4.14',
        '185.220.101.47',
        'CRITICAL',
        'sigma_zeek_ja3_c2_beacon.yml',
        'T1071.001',
        'Periodic 4.2s TLS 1.3 C2 beacon to cdn-sync-api.net (JA3 e7d705a3286e19ea42f587b344ee6865).'
      );

      this.pushAudit('CRITICAL', 'INCIDENT #AEGIS-901: Spear-Phishing Macro & TLS C2 Beacon active on Endpoint WS-14.');
    } else if (scenario === 'KERBEROAST_SMB') {
      this.activateTechniques(['T1068', 'T1558.003', 'T1003.001', 'T1021.002']);
      this.selectedTechniqueId = 'T1558.003';
      this.eps = 16890;
      this.mttdSeconds = 1.2;
      this.mttrSeconds = 56.4;

      this.applyDomainImpact([92.4, 59.8, 76.0, 84.0, 88.5]);

      this.iocs = [
        {
          type: 'SHA-256',
          value: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
          verdict: 'MALICIOUS',
        },
        {
          type: 'Kerberos / Account',
          value: 'SPN: MSSQLSvc/core-db-vault.abha.local:1433 (RC4 0x17)',
          verdict: 'MALICIOUS',
        },
        {
          type: 'C2 IP / Domain',
          value: 'Lateral SMB 445/TCP: 10.20.4.14 -> 10.10.1.10 (DC-01)',
          verdict: 'MALICIOUS',
        },
        {
          type: 'Process Lineage',
          value: 'powershell.exe -> Rubeus.exe kerberoast -> psexecsvc.exe',
          verdict: 'MALICIOUS',
        },
      ];

      this.pushLog(
        'Windows Event',
        'Event ID 4672',
        'AD-DC-01',
        '10.20.4.14',
        '10.10.1.10',
        'HIGH',
        'sigma_special_priv_assign.yml',
        'T1068',
        'Special privileges assigned (SeDebugPrivilege) to compromised session on Endpoint WS-14.'
      );
      this.pushLog(
        'Windows Event',
        'Event ID 4769',
        'AD-DC-01',
        '10.20.4.14',
        '10.10.1.10',
        'CRITICAL',
        'sigma_kerberoast_rc4_tgs.yml',
        'T1558.003',
        '19 Kerberos TGS-REQ tickets issued with TicketEncryptionType=0x17 (RC4-HMAC) in 14s.'
      );
      this.pushLog(
        'EDR Process Tree',
        'EDR-SMB-5140',
        'Core DB Vault',
        '10.20.4.14',
        '10.30.0.50',
        'CRITICAL',
        'sigma_smb_lateral_admin_share.yml',
        'T1021.002',
        'Lateral SMB Admin$ mount from WS-14 to Core DB Vault via stolen service ticket.'
      );

      this.pushAudit('CRITICAL', 'INCIDENT #AEGIS-902: Kerberoasting RC4 storm & SMB Lateral Movement toward DC-01 / Core DB.');
    } else if (scenario === 'RANSOMWARE_WIPE') {
      this.activateTechniques(['T1053.005', 'T1021.002', 'T1486', 'T1490']);
      this.selectedTechniqueId = 'T1486';
      this.eps = 24750;
      this.mttdSeconds = 0.9;
      this.mttrSeconds = 68.5;

      this.applyDomainImpact([89.5, 51.2, 46.8, 79.4, 71.0]);

      this.iocs = [
        {
          type: 'SHA-256',
          value: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
          verdict: 'MALICIOUS',
        },
        {
          type: 'Process Lineage',
          value: 'services.exe -> aegis_locker.exe -> vssadmin.exe delete shadows',
          verdict: 'MALICIOUS',
        },
        {
          type: 'C2 IP / Domain',
          value: '91.199.212.52:8443 (Exfil Tor/TLS Gate)',
          verdict: 'MALICIOUS',
        },
        {
          type: 'Kerberos / Account',
          value: 'svc_backup_admin (Privileged Vault Account)',
          verdict: 'MALICIOUS',
        },
      ];

      this.pushLog(
        'Windows Event',
        'Event ID 4688',
        'Core DB Vault',
        '10.30.0.50',
        '10.30.0.50',
        'CRITICAL',
        'sigma_vssadmin_shadow_wipe.yml',
        'T1490',
        'vssadmin.exe delete shadows /all /quiet executed under svc_backup_admin!'
      );
      this.pushLog(
        'EDR Process Tree',
        'EDR-FS-992',
        'Core DB Vault',
        '10.20.4.14',
        '10.30.0.50',
        'CRITICAL',
        'sigma_edr_ransom_entropy_burst.yml',
        'T1486',
        'Rapid ChaCha20 file encryption burst (480 files/sec -> *.aegis_enc) detected on Core DB Vault.'
      );
      this.pushLog(
        'Linux Auditd',
        'AUDIT-SYSCALL',
        'DMZ-Mail-01',
        '10.10.2.14',
        '91.199.212.52',
        'HIGH',
        'sigma_linux_auditd_privesc.yml',
        'T1548.003',
        'auditd: SYSCALL execve pid=4412 euid=0 comm="tar" staging /var/backups to egress socket.'
      );

      this.pushAudit('CRITICAL', 'INCIDENT #AEGIS-903: Ransomware Encryption & VSS Shadow Wipe detected! Immediate SOAR required.');
    }

    this.dfirPhases = [
      {
        id: 'preparation',
        label: 'Preparation',
        status: 'COMPLETED',
        timestamp: now,
        summary: 'Sigma rules & EDR telemetry sensors pre-deployed across perimeter and AD tiers.',
      },
      {
        id: 'detection',
        label: 'Detection & Analysis',
        status: 'ACTIVE',
        timestamp: now,
        summary: `High-confidence Sigma correlation matched (${scenario.replace('_', ' ')}).`,
      },
      {
        id: 'containment',
        label: 'Containment',
        status: 'PENDING',
        timestamp: '--:--:--',
        summary: 'Awaiting SOAR Playbook execution to isolate compromised host & revoke TGT.',
      },
      {
        id: 'eradication',
        label: 'Eradication',
        status: 'PENDING',
        timestamp: '--:--:--',
        summary: 'Pending process termination and persistence cleanup.',
      },
      {
        id: 'recovery',
        label: 'Recovery',
        status: 'PENDING',
        timestamp: '--:--:--',
        summary: 'Pending clean baseline verification & NCA ECC restoration.',
      },
    ];
  }

  public executeSoarPlaybook(): boolean {
    const now = formatUtcTime();

    this.contained = true;
    this.isolatedHosts = ['Endpoint WS-14', 'Core DB Vault'];
    this.revokedTgtCount += 14;
    this.eps = 5140;
    this.mttrSeconds = 4.6;

    // Mark all active MITRE techniques as contained
    this.mitreTechniques.forEach((t) => {
      if (t.active) {
        t.contained = true;
      }
    });

    // Elevate NCA ECC Compliance Readiness to exact 98.6% Compliant upon full containment
    const containedScores = [99.4, 98.8, 98.6, 98.1, 98.1]; // Avg = 98.6%
    this.ncaDomains.forEach((d, idx) => {
      d.currentScore = containedScores[idx];
      d.controlsPassed = d.controlsTotal;
    });

    this.iocs = this.iocs.map((ioc) => ({
      ...ioc,
      verdict: 'QUARANTINED',
    }));

    this.dfirPhases = [
      {
        id: 'preparation',
        label: 'Preparation',
        status: 'COMPLETED',
        timestamp: now,
        summary: 'NCA ECC telemetry sensors & SOAR playbooks verified.',
      },
      {
        id: 'detection',
        label: 'Detection & Analysis',
        status: 'COMPLETED',
        timestamp: now,
        summary: 'MITRE ATT&CK kill-chain & IOC SHA-256 fingerprints extracted.',
      },
      {
        id: 'containment',
        label: 'Containment',
        status: 'COMPLETED',
        timestamp: now,
        summary: 'EDR Network Quarantine Ring applied on Endpoint WS-14 & Core DB Vault.',
      },
      {
        id: 'eradication',
        label: 'Eradication',
        status: 'COMPLETED',
        timestamp: now,
        summary: 'Revoked 14 Kerberos TGTs, killed malicious PIDs & sinkholed C2 IPs at WAF.',
      },
      {
        id: 'recovery',
        label: 'Recovery',
        status: 'COMPLETED',
        timestamp: now,
        summary: 'NCA ECC Readiness restored to 98.6% Compliant — Zero residual lateral traffic.',
      },
    ];

    this.pushLog(
      'EDR Process Tree',
      'SOAR-ISOLATE',
      'Endpoint WS-14',
      '10.20.4.14',
      '0.0.0.0',
      'LOW',
      'soar_edr_quarantine_ring.yml',
      null,
      'SOAR Playbook isolated Endpoint WS-14 network stack & terminated rogue PowerShell/Locker PIDs.'
    );
    this.pushLog(
      'Windows Event',
      'KRBTGT-REVOKE',
      'AD-DC-01',
      '10.10.1.10',
      '10.20.4.14',
      'LOW',
      'soar_kerberos_tgt_purge.yml',
      null,
      'Revoked 14 active Kerberos TGT sessions & enforced MFA re-authentication under NCA ECC 2-2.'
    );

    this.pushAudit('SOAR', 'PLAYBOOK EXECUTED: Host WS-14 quarantined, 14 Kerberos TGTs revoked, WAF C2 egress sinkholed.');
    this.pushAudit('SOAR', 'NCA ECC Readiness elevated to 98.6% Compliant across all 5 control domains.');

    return true;
  }

  public step(dtSeconds: number): SeverityLevel | null {
    if (!this.running) return null;

    this.tickAccumulator += dtSeconds * this.speed;
    if (this.tickAccumulator < 0.72) return null;
    this.tickAccumulator = 0;

    let emittedSeverity: SeverityLevel = 'LOW';

    if (this.activeScenario !== 'NONE' && !this.contained) {
      emittedSeverity = this.emitScenarioLog();
      this.eps = Math.round(this.eps * 0.85 + (12000 + Math.random() * 9000) * 0.15);
    } else {
      emittedSeverity = this.emitBaselineLog();
      this.eps = Math.round(4700 + Math.random() * 480);
    }

    return emittedSeverity;
  }

  private activateTechniques(ids: string[]): void {
    this.mitreTechniques.forEach((t) => {
      if (ids.includes(t.id)) {
        t.active = true;
        t.contained = false;
        t.hits += 1;
      }
    });
  }

  private applyDomainImpact(scores: number[]): void {
    this.ncaDomains.forEach((d, idx) => {
      d.currentScore = scores[idx];
      d.controlsPassed = Math.max(1, Math.round((scores[idx] / 100) * d.controlsTotal));
    });
  }

  private emitBaselineLog(): SeverityLevel {
    const samples: Array<{
      source: LogSource;
      eventId: string;
      host: string;
      srcIp: string;
      dstIp: string;
      severity: SeverityLevel;
      sigmaRule: string | null;
      mitreId: string | null;
      message: string;
    }> = [
      {
        source: 'Windows Event',
        eventId: 'Event ID 4625',
        host: 'AD-DC-01',
        srcIp: '198.51.100.23',
        dstIp: '10.10.1.10',
        severity: 'MEDIUM',
        sigmaRule: 'sigma_4625_rdp_spray.yml',
        mitreId: null,
        message: 'Failed NTLM auth probe blocked by Perimeter WAF / AD Account Lockout policy.',
      },
      {
        source: 'Linux Auditd',
        eventId: 'AUDIT-SYSLOG',
        host: 'DMZ-Mail-01',
        srcIp: '10.10.2.14',
        dstIp: '10.10.1.10',
        severity: 'LOW',
        sigmaRule: null,
        mitreId: null,
        message: 'SYSCALL=openat uid=0 comm="sshd" verified PAM session key rotation.',
      },
      {
        source: 'Zeek DNS/TLS',
        eventId: 'ZEEK-TLS-1.3',
        host: 'Perimeter WAF',
        srcIp: '10.20.4.14',
        dstIp: '172.64.155.12',
        severity: 'LOW',
        sigmaRule: null,
        mitreId: null,
        message: 'Valid TLS 1.3 handshake to *.nca.gov.sa compliance feed (JA3 verified).',
      },
      {
        source: 'EDR Process Tree',
        eventId: 'EDR-TELEM',
        host: 'Endpoint WS-14',
        srcIp: '10.20.4.14',
        dstIp: '10.10.3.5',
        severity: 'LOW',
        sigmaRule: null,
        mitreId: null,
        message: 'Signed binary integrity check passed: MsMpEng.exe -> siem_forwarder.exe.',
      },
      {
        source: 'Perimeter WAF',
        eventId: 'WAF-CRS-942',
        host: 'Perimeter WAF',
        srcIp: '45.155.205.91',
        dstIp: '10.10.2.14',
        severity: 'MEDIUM',
        sigmaRule: 'sigma_waf_rce_probe.yml',
        mitreId: 'T1190',
        message: 'SQLi/JNDI scanner payload dropped at edge WAF (Rule 942100, Action: BLOCK).',
      },
    ];

    const pick = samples[Math.floor(Math.random() * samples.length)];
    this.pushLog(
      pick.source,
      pick.eventId,
      pick.host,
      pick.srcIp,
      pick.dstIp,
      pick.severity,
      pick.sigmaRule,
      pick.mitreId,
      pick.message
    );
    return pick.severity;
  }

  private emitScenarioLog(): SeverityLevel {
    if (this.activeScenario === 'PHISHING_C2') {
      const pool = [
        {
          source: 'Zeek DNS/TLS' as LogSource,
          eventId: 'ZEEK-DNS-TXT',
          host: 'Endpoint WS-14',
          srcIp: '10.20.4.14',
          dstIp: '185.220.101.47',
          severity: 'CRITICAL' as SeverityLevel,
          sigmaRule: 'sigma_zeek_ja3_c2_beacon.yml',
          mitreId: 'T1071.001',
          message: 'TLS C2 Heartbeat #tx-448 to cdn-sync-api.net (64B encrypted beacon payload).',
        },
        {
          source: 'EDR Process Tree' as LogSource,
          eventId: 'EDR-PROC-4688',
          host: 'Endpoint WS-14',
          srcIp: '10.20.4.14',
          dstIp: '185.220.101.47',
          severity: 'HIGH' as SeverityLevel,
          sigmaRule: 'sigma_ingress_payload_fetch.yml',
          mitreId: 'T1105',
          message: 'powershell.exe invoked WebClient.DownloadData() staging payload into memory.',
        },
      ];
      const pick = pool[Math.floor(Math.random() * pool.length)];
      this.pushLog(
        pick.source,
        pick.eventId,
        pick.host,
        pick.srcIp,
        pick.dstIp,
        pick.severity,
        pick.sigmaRule,
        pick.mitreId,
        pick.message
      );
      return pick.severity;
    }

    if (this.activeScenario === 'KERBEROAST_SMB') {
      const pool = [
        {
          source: 'Windows Event' as LogSource,
          eventId: 'Event ID 4769',
          host: 'AD-DC-01',
          srcIp: '10.20.4.14',
          dstIp: '10.10.1.10',
          severity: 'CRITICAL' as SeverityLevel,
          sigmaRule: 'sigma_kerberoast_rc4_tgs.yml',
          mitreId: 'T1558.003',
          message: 'Kerberos TGS-REQ RC4_HMAC_MD5 (0x17) requested for SPN HTTP/erp-vault.abha.local.',
        },
        {
          source: 'EDR Process Tree' as LogSource,
          eventId: 'EDR-LSASS-01',
          host: 'Endpoint WS-14',
          srcIp: '10.20.4.14',
          dstIp: '10.10.1.10',
          severity: 'CRITICAL' as SeverityLevel,
          sigmaRule: 'sigma_edr_lsass_read.yml',
          mitreId: 'T1003.001',
          message: 'Suspicious OpenProcess(PROCESS_VM_READ, 0x1010) against lsass.exe PID 692.',
        },
      ];
      const pick = pool[Math.floor(Math.random() * pool.length)];
      this.pushLog(
        pick.source,
        pick.eventId,
        pick.host,
        pick.srcIp,
        pick.dstIp,
        pick.severity,
        pick.sigmaRule,
        pick.mitreId,
        pick.message
      );
      return pick.severity;
    }

    // RANSOMWARE_WIPE
    const pool = [
      {
        source: 'EDR Process Tree' as LogSource,
        eventId: 'EDR-ENTROPY',
        host: 'Core DB Vault',
        srcIp: '10.20.4.14',
        dstIp: '10.30.0.50',
        severity: 'CRITICAL' as SeverityLevel,
        sigmaRule: 'sigma_edr_ransom_entropy_burst.yml',
        mitreId: 'T1486',
        message: 'Shannon entropy > 7.98 bits/byte on /srv/vault/ledger_*.db.aegis_enc!',
      },
      {
        source: 'Windows Event' as LogSource,
        eventId: 'Event ID 4688',
        host: 'Core DB Vault',
        srcIp: '10.30.0.50',
        dstIp: '10.30.0.50',
        severity: 'CRITICAL' as SeverityLevel,
        sigmaRule: 'sigma_vssadmin_shadow_wipe.yml',
        mitreId: 'T1490',
        message: 'wmic.exe shadowcopy delete /nointeractive triggered on Core DB Vault.',
      },
    ];
    const pick = pool[Math.floor(Math.random() * pool.length)];
    this.pushLog(
      pick.source,
      pick.eventId,
      pick.host,
      pick.srcIp,
      pick.dstIp,
      pick.severity,
      pick.sigmaRule,
      pick.mitreId,
      pick.message
    );
    return pick.severity;
  }

  private pushLog(
    source: LogSource,
    eventId: string,
    host: string,
    srcIp: string,
    dstIp: string,
    severity: SeverityLevel,
    sigmaRule: string | null,
    mitreId: string | null,
    message: string
  ): void {
    this.logSeq += 1;
    this.totalEvents += Math.floor(14 + Math.random() * 28);
    this.severityCounts[severity] += 1;

    if (mitreId) {
      const tech = this.mitreTechniques.find((t) => t.id === mitreId);
      if (tech) {
        tech.hits += 1;
      }
    }

    this.logs.unshift({
      id: this.logSeq,
      timestamp: formatUtcTime(),
      source,
      eventId,
      host,
      srcIp,
      dstIp,
      severity,
      sigmaRule,
      mitreId,
      message,
    });

    if (this.logs.length > 42) {
      this.logs.pop();
    }
  }

  private pushAudit(level: SoarAuditEntry['level'], message: string): void {
    this.auditSeq += 1;
    this.soarAudit.unshift({
      id: this.auditSeq,
      timestamp: formatUtcTime(),
      level,
      message,
    });
    if (this.soarAudit.length > 24) {
      this.soarAudit.pop();
    }
  }

  public getSnapshot(): SocSnapshot {
    const avgCompliance =
      this.ncaDomains.reduce((acc, d) => acc + d.currentScore, 0) / this.ncaDomains.length;
    const roundedCompliance = Math.round(avgCompliance * 10) / 10;

    let complianceStatusLabel = 'BASELINE MONITORED';
    if (this.contained) {
      complianceStatusLabel = `${roundedCompliance.toFixed(1)}% Compliant`;
    } else if (this.activeScenario !== 'NONE') {
      complianceStatusLabel = 'AT RISK • INCIDENT ACTIVE';
    } else {
      complianceStatusLabel = `${roundedCompliance.toFixed(1)}% Compliant`;
    }

    return {
      running: this.running,
      speed: this.speed,
      activeScenario: this.activeScenario,
      contained: this.contained,
      eps: this.eps,
      totalEvents: this.totalEvents,
      mttdSeconds: this.mttdSeconds,
      mttrSeconds: this.mttrSeconds,
      severityCounts: { ...this.severityCounts },
      overallCompliance: roundedCompliance,
      complianceStatusLabel,
      ncaDomains: this.ncaDomains.map((d) => ({ ...d })),
      mitreTechniques: this.mitreTechniques.map((t) => ({ ...t })),
      selectedTechniqueId: this.selectedTechniqueId,
      logs: [...this.logs],
      dfirPhases: this.dfirPhases.map((p) => ({ ...p })),
      iocs: this.iocs.map((i) => ({ ...i })),
      soarAudit: [...this.soarAudit],
      isolatedHosts: [...this.isolatedHosts],
      revokedTgtCount: this.revokedTgtCount,
    };
  }
}
