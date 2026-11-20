/**
 * SIEM-AEGIS: Application Bootstrap & SOC Telemetry HUD Orchestrator
 * Lead Architect: أ. طارق ابوعشي | Tareq Abuashi — Cybersecurity & Distributed Systems Architect
 */

import { SocCanvas } from './components/SocCanvas';
import {
  MITRE_TACTIC_COLUMNS,
  SiemEngine,
  type MitreTechnique,
  type SocSnapshot,
} from './engine/siemEngine';
import { SocAudioEngine } from './utils/audio';

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function getRequiredEl<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) {
    throw new Error(`Missing required DOM element: #${id}`);
  }
  return el as T;
}

class SiemAegisApp {
  private engine = new SiemEngine();
  private audio = new SocAudioEngine();
  private canvasController: SocCanvas;

  private activeLogFilter = 'ALL';
  private lastRenderTime = performance.now();
  private fpsAccum = 0;
  private fpsFrames = 0;
  private lastUiSync = 0;

  // DOM References
  private hudFps = getRequiredEl<HTMLSpanElement>('hud-fps');
  private hudIncidentBadge = getRequiredEl<HTMLDivElement>('hud-incident-badge');
  private socPulseDot = getRequiredEl<HTMLSpanElement>('soc-pulse-dot');

  private kpiEps = getRequiredEl<HTMLSpanElement>('kpi-eps');
  private kpiTotalEvents = getRequiredEl<HTMLSpanElement>('kpi-total-events');
  private kpiMttdMttr = getRequiredEl<HTMLSpanElement>('kpi-mttd-mttr');
  private kpiTgtRevoked = getRequiredEl<HTMLSpanElement>('kpi-tgt-revoked');
  private kpiAlertsCount = getRequiredEl<HTMLSpanElement>('kpi-alerts-count');
  private kpiAlertsSub = getRequiredEl<HTMLSpanElement>('kpi-alerts-sub');
  private kpiNcaOverall = getRequiredEl<HTMLSpanElement>('kpi-nca-overall');
  private kpiNcaStatus = getRequiredEl<HTMLSpanElement>('kpi-nca-status');

  private mitreMatrixGrid = getRequiredEl<HTMLDivElement>('mitre-matrix-grid');
  private mitreActiveBadge = getRequiredEl<HTMLSpanElement>('mitre-active-badge');
  private inspectorTitle = getRequiredEl<HTMLDivElement>('inspector-title');
  private inspectorDesc = getRequiredEl<HTMLParagraphElement>('inspector-desc');
  private inspectorNca = getRequiredEl<HTMLDivElement>('inspector-nca');
  private inspectorSigmaYaml = getRequiredEl<HTMLPreElement>('inspector-sigma-yaml');

  private siemLogTbody = getRequiredEl<HTMLTableSectionElement>('siem-log-tbody');
  private ncaReadinessBadge = getRequiredEl<HTMLSpanElement>('nca-readiness-badge');
  private ncaBigScore = getRequiredEl<HTMLDivElement>('nca-big-score');
  private ncaControlsSummary = getRequiredEl<HTMLDivElement>('nca-controls-summary');
  private ncaDomainsList = getRequiredEl<HTMLDivElement>('nca-domains-list');

  private dfirPhaseBadge = getRequiredEl<HTMLSpanElement>('dfir-phase-badge');
  private dfirTimeline = getRequiredEl<HTMLDivElement>('dfir-timeline');
  private iocList = getRequiredEl<HTMLDivElement>('ioc-list');
  private soarAuditLog = getRequiredEl<HTMLDivElement>('soar-audit-log');

  private audioToggleBtn = getRequiredEl<HTMLButtonElement>('audio-toggle-btn');
  private audioStatusText = getRequiredEl<HTMLSpanElement>('audio-status-text');
  private dossierModal = getRequiredEl<HTMLDivElement>('dossier-modal');

  private btnPhishC2 = getRequiredEl<HTMLButtonElement>('btn-phish-c2');
  private btnKerberoastSmb = getRequiredEl<HTMLButtonElement>('btn-kerberoast-smb');
  private btnRansomwareWipe = getRequiredEl<HTMLButtonElement>('btn-ransomware-wipe');
  private btnSoarContain = getRequiredEl<HTMLButtonElement>('btn-soar-contain');
  private btnResetSoc = getRequiredEl<HTMLButtonElement>('btn-reset-soc');
  private btnPlayPause = getRequiredEl<HTMLButtonElement>('btn-play-pause');
  private txtPlayPause = getRequiredEl<HTMLSpanElement>('txt-play-pause');

  constructor() {
    const canvas = getRequiredEl<HTMLCanvasElement>('soc-canvas');
    this.canvasController = new SocCanvas(canvas);
    this.bindEvents();
    this.syncUi(this.engine.getSnapshot());
    requestAnimationFrame(this.loop);
  }

  private bindEvents(): void {
    window.addEventListener('resize', () => {
      this.canvasController.resize();
    });

    // Audio Toggle
    this.audioToggleBtn.addEventListener('click', () => {
      const enabled = this.audio.toggle();
      this.audioToggleBtn.classList.toggle('active', enabled);
      this.audioStatusText.textContent = enabled ? 'Audio: ON' : 'Audio: OFF';
      if (enabled) this.audio.playUiConfirm();
    });

    // Dossier Modal
    const openDossierBtn = getRequiredEl<HTMLButtonElement>('open-dossier-btn');
    const closeDossierBtn = getRequiredEl<HTMLButtonElement>('close-dossier-btn');
    const closeDossierFooterBtn = getRequiredEl<HTMLButtonElement>('close-dossier-footer-btn');

    const closeModal = (): void => {
      this.dossierModal.classList.add('hidden');
      this.audio.playUiConfirm();
    };

    openDossierBtn.addEventListener('click', () => {
      this.dossierModal.classList.remove('hidden');
      this.audio.playUiConfirm();
    });
    closeDossierBtn.addEventListener('click', closeModal);
    closeDossierFooterBtn.addEventListener('click', closeModal);
    this.dossierModal.addEventListener('click', (e) => {
      if (e.target === this.dossierModal) closeModal();
    });
    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && !this.dossierModal.classList.contains('hidden')) {
        closeModal();
      }
    });

    // Attack Scenario Injection Buttons
    this.btnPhishC2.addEventListener('click', () => {
      this.engine.injectScenario('PHISHING_C2');
      this.audio.playSocAlert();
      this.syncUi(this.engine.getSnapshot());
    });

    this.btnKerberoastSmb.addEventListener('click', () => {
      this.engine.injectScenario('KERBEROAST_SMB');
      this.audio.playSocAlert();
      this.syncUi(this.engine.getSnapshot());
    });

    this.btnRansomwareWipe.addEventListener('click', () => {
      this.engine.injectScenario('RANSOMWARE_WIPE');
      this.audio.playSocAlert();
      this.syncUi(this.engine.getSnapshot());
    });

    this.btnSoarContain.addEventListener('click', () => {
      this.engine.executeSoarPlaybook();
      this.audio.playSoarContainment();
      this.syncUi(this.engine.getSnapshot());
    });

    this.btnResetSoc.addEventListener('click', () => {
      this.engine.resetBaseline();
      this.audio.playUiConfirm();
      this.syncUi(this.engine.getSnapshot());
    });

    // Play/Pause & Speed Controls
    this.btnPlayPause.addEventListener('click', () => {
      const next = !this.engine.isRunning();
      this.engine.setRunning(next);
      this.btnPlayPause.classList.toggle('active', next);
      this.txtPlayPause.textContent = next ? 'Live' : 'Paused';
      this.audio.playUiConfirm();
    });

    document.querySelectorAll<HTMLButtonElement>('.speed-btn').forEach((btn) => {
      btn.addEventListener('click', () => {
        const speed = Number(btn.dataset.speed || '1');
        this.engine.setSpeed(speed);
        document.querySelectorAll('.speed-btn').forEach((b) => b.classList.remove('active'));
        btn.classList.add('active');
        this.audio.playUiConfirm();
      });
    });

    // Log Source & Severity Filters
    document.querySelectorAll<HTMLButtonElement>('.filter-chip').forEach((chip) => {
      chip.addEventListener('click', () => {
        this.activeLogFilter = chip.dataset.filter || 'ALL';
        document.querySelectorAll('.filter-chip').forEach((c) => c.classList.remove('active'));
        chip.classList.add('active');
        this.renderLogs(this.engine.getSnapshot());
        this.audio.playUiConfirm();
      });
    });

    // MITRE ATT&CK Technique Click Delegation
    this.mitreMatrixGrid.addEventListener('click', (e) => {
      const btn = (e.target as HTMLElement).closest<HTMLButtonElement>('.mitre-tech-btn');
      if (!btn || !btn.dataset.techId) return;
      this.engine.selectTechnique(btn.dataset.techId);
      this.audio.playUiConfirm();
      this.syncUi(this.engine.getSnapshot());
    });
  }

  private loop = (now: number): void => {
    const dt = Math.min((now - this.lastRenderTime) / 1000, 0.1);
    this.lastRenderTime = now;

    // FPS Counter
    this.fpsAccum += dt;
    this.fpsFrames += 1;
    if (this.fpsAccum >= 0.5) {
      const fps = Math.round(this.fpsFrames / this.fpsAccum);
      this.hudFps.textContent = `${fps} FPS`;
      this.fpsAccum = 0;
      this.fpsFrames = 0;
    }

    const emitted = this.engine.step(dt);
    const snap = this.engine.getSnapshot();

    this.canvasController.setState(snap.activeScenario, snap.contained, snap.running, snap.speed);
    this.canvasController.render(dt);

    if (emitted) {
      this.audio.playTelemetryTick(emitted);
    }

    if (emitted || now - this.lastUiSync > 350) {
      this.lastUiSync = now;
      this.syncUi(snap);
    }

    requestAnimationFrame(this.loop);
  };

  private syncUi(snap: SocSnapshot): void {
    // Active Toolbar Highlights
    this.btnPhishC2.classList.toggle('active', snap.activeScenario === 'PHISHING_C2' && !snap.contained);
    this.btnKerberoastSmb.classList.toggle('active', snap.activeScenario === 'KERBEROAST_SMB' && !snap.contained);
    this.btnRansomwareWipe.classList.toggle('active', snap.activeScenario === 'RANSOMWARE_WIPE' && !snap.contained);
    this.btnSoarContain.classList.toggle('active', snap.contained);

    // Canvas Top HUD Status
    this.hudIncidentBadge.classList.remove('attack', 'contained');
    this.socPulseDot.classList.remove('danger');
    if (snap.contained) {
      this.hudIncidentBadge.textContent = 'CONTAINED • SOAR QUARANTINE RING ACTIVE';
      this.hudIncidentBadge.classList.add('contained');
    } else if (snap.activeScenario !== 'NONE') {
      this.hudIncidentBadge.textContent = `INCIDENT ACTIVE • ${snap.activeScenario.replace('_', ' ')}`;
      this.hudIncidentBadge.classList.add('attack');
      this.socPulseDot.classList.add('danger');
    } else {
      this.hudIncidentBadge.textContent = 'BASELINE • SOC MONITORING ACTIVE';
    }

    // KPI Strip
    this.kpiEps.textContent = `${snap.eps.toLocaleString()} EPS`;
    this.kpiTotalEvents.textContent = `${snap.totalEvents.toLocaleString()} Correlated Events`;
    this.kpiMttdMttr.textContent = `${snap.mttdSeconds.toFixed(1)}s / ${snap.mttrSeconds.toFixed(1)}s`;
    this.kpiTgtRevoked.textContent = `SOAR TGT Revocations: ${snap.revokedTgtCount}`;
    this.kpiAlertsCount.textContent = `${snap.severityCounts.CRITICAL} CRIT • ${snap.severityCounts.HIGH} HIGH`;
    this.kpiAlertsSub.textContent = `${snap.severityCounts.MEDIUM} MED • ${snap.severityCounts.LOW} LOW`;

    this.kpiNcaOverall.textContent = `${snap.overallCompliance.toFixed(1)}%`;
    this.kpiNcaStatus.textContent = snap.complianceStatusLabel;
    this.kpiNcaOverall.classList.remove('emerald', 'amber', 'crimson');
    if (snap.overallCompliance >= 95) {
      this.kpiNcaOverall.classList.add('emerald');
    } else if (snap.overallCompliance >= 80) {
      this.kpiNcaOverall.classList.add('amber');
    } else {
      this.kpiNcaOverall.classList.add('crimson');
    }

    this.renderMitreMatrix(snap);
    this.renderLogs(snap);
    this.renderNcaCompliance(snap);
    this.renderDfirAndIocs(snap);
    this.renderSoarAudit(snap);
  }

  private renderMitreMatrix(snap: SocSnapshot): void {
    const activeCount = snap.mitreTechniques.filter((t) => t.active && !t.contained).length;
    if (snap.contained) {
      this.mitreActiveBadge.textContent = 'ALL ACTIVE TECHNIQUES CONTAINED BY SOAR';
      this.mitreActiveBadge.className = 'badge emerald';
    } else if (activeCount > 0) {
      this.mitreActiveBadge.textContent = `${activeCount} ACTIVE TECHNIQUES DETECTED`;
      this.mitreActiveBadge.className = 'badge crimson';
    } else {
      this.mitreActiveBadge.textContent = 'CLICK ANY TECHNIQUE FOR SIGMA RULE';
      this.mitreActiveBadge.className = 'badge cyan';
    }

    this.mitreMatrixGrid.innerHTML = MITRE_TACTIC_COLUMNS.map((col) => {
      const techs = snap.mitreTechniques.filter((t) => t.tacticId === col.id);
      const cards = techs
        .map((t) => {
          const classes = ['mitre-tech-btn'];
          if (t.id === snap.selectedTechniqueId) classes.push('selected');
          if (t.active && !t.contained) classes.push('active-hit');
          else if (t.active && t.contained) classes.push('contained-hit');

          return `
            <button type="button" class="${classes.join(' ')}" data-tech-id="${escapeHtml(t.id)}">
              <div class="mitre-tech-top">
                <span class="mitre-id">${escapeHtml(t.id)}</span>
                <span class="mitre-hits">${t.hits}</span>
              </div>
              <div class="mitre-tech-name">${escapeHtml(t.name)}</div>
            </button>
          `;
        })
        .join('');

      return `
        <div class="mitre-col">
          <div class="mitre-col-head">
            <span class="mitre-tactic-code">${escapeHtml(col.shortCode)}</span>
            <span class="mitre-tactic-name" title="${escapeHtml(col.label)}">${escapeHtml(col.label)}</span>
          </div>
          ${cards}
        </div>
      `;
    }).join('');

    const selected: MitreTechnique | undefined = snap.mitreTechniques.find(
      (t) => t.id === snap.selectedTechniqueId
    );
    if (selected) {
      this.inspectorTitle.textContent = `${selected.id} • ${selected.name} (${selected.tacticLabel})`;
      this.inspectorDesc.textContent = selected.description;
      this.inspectorNca.textContent = `NCA ECC Control: ${selected.ncaControl} • Sigma Rule: ${selected.sigmaTitle}`;
      this.inspectorSigmaYaml.textContent = selected.sigmaYaml;
    }
  }

  private renderLogs(snap: SocSnapshot): void {
    const filtered = snap.logs.filter((entry) => {
      if (this.activeLogFilter === 'ALL') return true;
      if (this.activeLogFilter === 'CRITICAL' || this.activeLogFilter === 'HIGH') {
        return entry.severity === this.activeLogFilter;
      }
      return entry.source === this.activeLogFilter;
    });

    this.siemLogTbody.innerHTML = filtered
      .slice(0, 18)
      .map((entry) => {
        const tag = entry.mitreId
          ? `<span style="color:#fda4af;font-weight:700">[${escapeHtml(entry.mitreId)}]</span> `
          : '';
        const sigma = entry.sigmaRule
          ? `<div style="color:#38bdf8;font-size:0.58rem">Sigma: ${escapeHtml(entry.sigmaRule)}</div>`
          : '';

        return `
          <tr>
            <td>${escapeHtml(entry.timestamp)}</td>
            <td>${escapeHtml(entry.source)}</td>
            <td>${escapeHtml(entry.eventId)}</td>
            <td>${escapeHtml(entry.host)}<br><span style="color:#64748b">${escapeHtml(entry.srcIp)} &rarr; ${escapeHtml(entry.dstIp)}</span></td>
            <td><span class="sev-badge ${entry.severity}">${entry.severity}</span></td>
            <td>${tag}${escapeHtml(entry.message)}${sigma}</td>
          </tr>
        `;
      })
      .join('');
  }

  private renderNcaCompliance(snap: SocSnapshot): void {
    const passedTotal = snap.ncaDomains.reduce((a, d) => a + d.controlsPassed, 0);
    const controlsTotal = snap.ncaDomains.reduce((a, d) => a + d.controlsTotal, 0);

    this.ncaBigScore.textContent = `${snap.overallCompliance.toFixed(1)}%`;
    this.ncaControlsSummary.textContent = `${passedTotal} / ${controlsTotal} NCA ECC Controls Verified`;
    this.ncaReadinessBadge.textContent = snap.complianceStatusLabel;

    this.ncaBigScore.classList.remove('warn', 'danger');
    this.ncaReadinessBadge.className = 'badge emerald';

    if (snap.overallCompliance < 80) {
      this.ncaBigScore.classList.add('danger');
      this.ncaReadinessBadge.className = 'badge crimson';
    } else if (snap.overallCompliance < 95) {
      this.ncaBigScore.classList.add('warn');
      this.ncaReadinessBadge.className = 'badge amber';
    }

    this.ncaDomainsList.innerHTML = snap.ncaDomains
      .map((domain) => {
        const barClass =
          domain.currentScore >= 90
            ? 'bar-fill-emerald'
            : domain.currentScore >= 72
              ? 'bar-fill-amber'
              : 'bar-fill-crimson';
        const valClass =
          domain.currentScore >= 90
            ? 'emerald'
            : domain.currentScore >= 72
              ? 'amber'
              : 'crimson';

        return `
          <div class="domain-row">
            <div class="control-label-row">
              <span>${escapeHtml(domain.title)}</span>
              <span class="control-val ${valClass}">${domain.currentScore.toFixed(1)}%</span>
            </div>
            <div class="energy-bar-wrap">
              <div class="${barClass}" style="width: ${Math.max(4, Math.min(100, domain.currentScore))}%;"></div>
            </div>
          </div>
        `;
      })
      .join('');
  }

  private renderDfirAndIocs(snap: SocSnapshot): void {
    const activePhase =
      snap.dfirPhases.find((p) => p.status === 'ACTIVE') ||
      snap.dfirPhases[snap.dfirPhases.length - 1];
    this.dfirPhaseBadge.textContent = activePhase.label.toUpperCase();
    this.dfirPhaseBadge.className = snap.contained
      ? 'badge emerald'
      : snap.activeScenario !== 'NONE'
        ? 'badge crimson'
        : 'badge amber';

    this.dfirTimeline.innerHTML = snap.dfirPhases
      .map(
        (phase) => `
        <div class="dfir-step ${phase.status}">
          <div class="dfir-step-head">
            <span>${escapeHtml(phase.label)}</span>
            <span style="color:#94a3b8">${escapeHtml(phase.timestamp)} &bull; ${phase.status}</span>
          </div>
          <div class="dfir-step-summary">${escapeHtml(phase.summary)}</div>
        </div>
      `
      )
      .join('');

    this.iocList.innerHTML = snap.iocs
      .map((ioc) => {
        const badgeCls = ioc.verdict === 'QUARANTINED' ? 'LOW' : ioc.verdict === 'SUSPICIOUS' ? 'HIGH' : 'CRITICAL';
        return `
          <div class="ioc-row">
            <div class="ioc-head">
              <span style="color:#06b6d4;font-weight:700">${escapeHtml(ioc.type)}</span>
              <span class="sev-badge ${badgeCls}">${ioc.verdict}</span>
            </div>
            <div class="ioc-val">${escapeHtml(ioc.value)}</div>
          </div>
        `;
      })
      .join('');
  }

  private renderSoarAudit(snap: SocSnapshot): void {
    this.soarAuditLog.innerHTML = snap.soarAudit
      .map(
        (item) => `
        <div class="event-item ${item.level}">
          <strong>[${escapeHtml(item.timestamp)}]</strong> ${escapeHtml(item.message)}
        </div>
      `
      )
      .join('');
  }
}

window.addEventListener('DOMContentLoaded', () => {
  new SiemAegisApp();
});
