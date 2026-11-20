/**
 * SIEM-AEGIS: 60fps Enterprise Kill-Chain Topology & SOAR Quarantine Canvas
 * Lead Architect: أ. طارق ابوعشي | Tareq Abuashi — Cybersecurity & Distributed Systems Architect
 */

import type { IncidentScenarioId } from '../engine/siemEngine';

interface TopologyNode {
  id: string;
  label: string;
  sublabel: string;
  ip: string;
  nx: number;
  ny: number;
  zone: 'EDGE' | 'DMZ' | 'IDENTITY' | 'ENDPOINT' | 'CROWN';
}

interface TelemetryPacket {
  fromIdx: number;
  toIdx: number;
  t: number;
  speed: number;
  kind: 'NORMAL' | 'LATERAL' | 'C2' | 'BLOCKED';
}

const ENTERPRISE_NODES: TopologyNode[] = [
  {
    id: 'waf',
    label: 'Perimeter WAF',
    sublabel: 'Edge NGFW / DPI',
    ip: '198.51.100.1',
    nx: 0.11,
    ny: 0.52,
    zone: 'EDGE',
  },
  {
    id: 'dmz',
    label: 'DMZ Mail/Web',
    sublabel: 'SMTP & Reverse Proxy',
    ip: '10.10.2.14',
    nx: 0.30,
    ny: 0.52,
    zone: 'DMZ',
  },
  {
    id: 'dc',
    label: 'Active Directory DC-01',
    sublabel: 'Kerberos KDC / IAM',
    ip: '10.10.1.10',
    nx: 0.50,
    ny: 0.52,
    zone: 'IDENTITY',
  },
  {
    id: 'ws',
    label: 'Endpoint WS-14',
    sublabel: 'EDR Sensor Host',
    ip: '10.20.4.14',
    nx: 0.70,
    ny: 0.52,
    zone: 'ENDPOINT',
  },
  {
    id: 'db',
    label: 'Core DB Vault',
    sublabel: 'Tier-0 Crown Jewels',
    ip: '10.30.0.50',
    nx: 0.89,
    ny: 0.52,
    zone: 'CROWN',
  },
];

export class SocCanvas {
  private canvas: HTMLCanvasElement;
  private ctx: CanvasRenderingContext2D;
  private width = 0;
  private height = 0;
  private dpr = 1;

  private packets: TelemetryPacket[] = [];
  private spawnTimer = 0;
  private elapsed = 0;

  private scenario: IncidentScenarioId = 'NONE';
  private contained = false;
  private running = true;
  private speed = 1;

  constructor(canvas: HTMLCanvasElement) {
    this.canvas = canvas;
    const context = canvas.getContext('2d');
    if (!context) {
      throw new Error('2D canvas context unavailable');
    }
    this.ctx = context;
    this.resize();
  }

  public resize(): void {
    const rect = this.canvas.getBoundingClientRect();
    this.dpr = Math.min(window.devicePixelRatio || 1, 2);
    this.width = Math.max(320, rect.width);
    this.height = Math.max(240, rect.height);
    this.canvas.width = Math.round(this.width * this.dpr);
    this.canvas.height = Math.round(this.height * this.dpr);
    this.ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
  }

  public setState(
    scenario: IncidentScenarioId,
    contained: boolean,
    running: boolean,
    speed: number
  ): void {
    this.scenario = scenario;
    this.contained = contained;
    this.running = running;
    this.speed = speed;
  }

  public render(dtSeconds: number): void {
    if (this.running) {
      const scaledDt = dtSeconds * this.speed;
      this.elapsed += scaledDt;
      this.spawnTimer += scaledDt;

      const spawnInterval = this.scenario !== 'NONE' && !this.contained ? 0.085 : 0.19;
      while (this.spawnTimer >= spawnInterval) {
        this.spawnTimer -= spawnInterval;
        this.spawnPacket();
      }

      for (let i = this.packets.length - 1; i >= 0; i--) {
        const p = this.packets[i];
        p.t += p.speed * scaledDt;
        if (p.t >= 1) {
          this.packets.splice(i, 1);
        }
      }
    }

    this.drawScene();
  }

  private spawnPacket(): void {
    if (this.packets.length > 90) return;

    if (this.scenario === 'NONE' || this.contained) {
      const pairIdx = Math.floor(Math.random() * 4);
      const forward = Math.random() > 0.35;
      this.packets.push({
        fromIdx: forward ? pairIdx : pairIdx + 1,
        toIdx: forward ? pairIdx + 1 : pairIdx,
        t: 0,
        speed: 0.65 + Math.random() * 0.45,
        kind: this.contained && pairIdx >= 2 && Math.random() < 0.25 ? 'BLOCKED' : 'NORMAL',
      });
      return;
    }

    if (this.scenario === 'PHISHING_C2') {
      const r = Math.random();
      if (r < 0.42) {
        // Mail -> WS-14 phishing delivery
        this.packets.push({ fromIdx: 1, toIdx: 3, t: 0, speed: 0.9, kind: 'LATERAL' });
      } else if (r < 0.8) {
        // WS-14 -> External C2 beacon through WAF
        this.packets.push({ fromIdx: 3, toIdx: 0, t: 0, speed: 1.15, kind: 'C2' });
      } else {
        this.packets.push({ fromIdx: 0, toIdx: 1, t: 0, speed: 0.7, kind: 'NORMAL' });
      }
      return;
    }

    if (this.scenario === 'KERBEROAST_SMB') {
      const r = Math.random();
      if (r < 0.45) {
        // WS-14 <-> DC-01 Kerberoasting TGS storm
        this.packets.push({ fromIdx: 3, toIdx: 2, t: 0, speed: 1.25, kind: 'LATERAL' });
      } else if (r < 0.85) {
        // WS-14 -> Core DB Vault SMB lateral arc
        this.packets.push({ fromIdx: 3, toIdx: 4, t: 0, speed: 1.05, kind: 'LATERAL' });
      } else {
        this.packets.push({ fromIdx: 2, toIdx: 3, t: 0, speed: 1.1, kind: 'C2' });
      }
      return;
    }

    // RANSOMWARE_WIPE
    const r = Math.random();
    if (r < 0.55) {
      // Lateral encryption burst WS-14 -> Core DB Vault
      this.packets.push({ fromIdx: 3, toIdx: 4, t: 0, speed: 1.4, kind: 'LATERAL' });
    } else {
      // C2 Exfiltration arc Core DB -> WAF
      this.packets.push({ fromIdx: 4, toIdx: 0, t: 0, speed: 1.1, kind: 'C2' });
    }
  }

  private drawScene(): void {
    const ctx = this.ctx;
    const w = this.width;
    const h = this.height;

    ctx.clearRect(0, 0, w, h);

    // Subtle cyber telemetry grid
    ctx.save();
    ctx.strokeStyle = 'rgba(6, 182, 212, 0.06)';
    ctx.lineWidth = 1;
    const gridSize = 34;
    for (let x = 0; x < w; x += gridSize) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, h);
      ctx.stroke();
    }
    for (let y = 0; y < h; y += gridSize) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(w, y);
      ctx.stroke();
    }
    ctx.restore();

    const coords = ENTERPRISE_NODES.map((node) => ({
      node,
      x: node.nx * w,
      y: node.ny * h,
    }));

    // Draw baseline enterprise backbone links (WAF <- DMZ <- DC-01 <- WS-14 <- DB Vault)
    for (let i = 0; i < coords.length - 1; i++) {
      const a = coords[i];
      const b = coords[i + 1];
      ctx.save();
      ctx.strokeStyle = 'rgba(6, 182, 212, 0.25)';
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.lineTo(b.x, b.y);
      ctx.stroke();

      // Subtle directional chevron indicating trust boundary flow
      const midX = (a.x + b.x) / 2;
      const midY = (a.y + b.y) / 2;
      ctx.fillStyle = 'rgba(6, 182, 212, 0.45)';
      ctx.beginPath();
      ctx.arc(midX, midY, 2.5, 0, Math.PI * 2);
      ctx.fill();
      ctx.restore();
    }

    // Draw Lateral Movement Arcs when attack is active and uncontained
    if (this.scenario !== 'NONE' && !this.contained) {
      this.drawLateralArcs(ctx, coords);
      this.drawC2Beaconing(ctx, coords);
    }

    // Draw flying telemetry packets
    for (const pkt of this.packets) {
      const src = coords[pkt.fromIdx];
      const dst = coords[pkt.toIdx];
      const pos = this.interpolatePath(src, dst, pkt.t, pkt.kind);

      ctx.save();
      let color = '#10b981';
      let radius = 3.2;
      if (pkt.kind === 'LATERAL') {
        color = '#f43f5e';
        radius = 4.2;
      } else if (pkt.kind === 'C2') {
        color = '#f59e0b';
        radius = 3.8;
      } else if (pkt.kind === 'BLOCKED') {
        color = '#38bdf8';
        radius = 3.0;
      }

      ctx.shadowColor = color;
      ctx.shadowBlur = 10;
      ctx.fillStyle = color;
      ctx.beginPath();
      ctx.arc(pos.x, pos.y, radius, 0, Math.PI * 2);
      ctx.fill();
      ctx.restore();
    }

    // Draw Enterprise Nodes & SOAR Quarantine Rings
    coords.forEach(({ node, x, y }, idx) => {
      this.drawNode(ctx, node, x, y, idx);
    });
  }

  private interpolatePath(
    src: { x: number; y: number },
    dst: { x: number; y: number },
    t: number,
    kind: TelemetryPacket['kind']
  ): { x: number; y: number } {
    if (kind === 'NORMAL' || kind === 'BLOCKED') {
      return {
        x: src.x + (dst.x - src.x) * t,
        y: src.y + (dst.y - src.y) * t,
      };
    }

    // Quadratic bezier arc for Lateral Movement / C2 Beaconing
    const lift = kind === 'C2' ? -78 : 74;
    const ctrlX = (src.x + dst.x) / 2;
    const ctrlY = (src.y + dst.y) / 2 + lift;
    const inv = 1 - t;
    return {
      x: inv * inv * src.x + 2 * inv * t * ctrlX + t * t * dst.x,
      y: inv * inv * src.y + 2 * inv * t * ctrlY + t * t * dst.y,
    };
  }

  private drawLateralArcs(
    ctx: CanvasRenderingContext2D,
    coords: Array<{ node: TopologyNode; x: number; y: number }>
  ): void {
    const pairs: Array<[number, number, string]> =
      this.scenario === 'PHISHING_C2'
        ? [[1, 3, 'Spear-Phish Macro Drop']]
        : this.scenario === 'KERBEROAST_SMB'
          ? [
              [3, 2, 'Kerberoast RC4 (T1558)'],
              [3, 4, 'SMB Admin$ Lateral (T1021)'],
            ]
          : [
              [3, 4, 'Ransomware Encrypt (T1486)'],
              [2, 4, 'Shadow Wipe (T1490)'],
            ];

    ctx.save();
    for (const [aIdx, bIdx, label] of pairs) {
      const a = coords[aIdx];
      const b = coords[bIdx];
      const ctrlX = (a.x + b.x) / 2;
      const ctrlY = (a.y + b.y) / 2 + 74;

      ctx.strokeStyle = 'rgba(244, 63, 94, 0.72)';
      ctx.lineWidth = 2;
      ctx.setLineDash([7, 5]);
      ctx.lineDashOffset = -this.elapsed * 38;

      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.quadraticCurveTo(ctrlX, ctrlY, b.x, b.y);
      ctx.stroke();

      ctx.setLineDash([]);
      ctx.font = '600 10px "Fira Code", monospace';
      ctx.fillStyle = '#fda4af';
      ctx.textAlign = 'center';
      ctx.fillText(label, ctrlX, ctrlY - 12);
    }
    ctx.restore();
  }

  private drawC2Beaconing(
    ctx: CanvasRenderingContext2D,
    coords: Array<{ node: TopologyNode; x: number; y: number }>
  ): void {
    const srcIdx = this.scenario === 'RANSOMWARE_WIPE' ? 4 : 3;
    const src = coords[srcIdx];
    const waf = coords[0];
    const ctrlX = (src.x + waf.x) / 2;
    const ctrlY = (src.y + waf.y) / 2 - 78;

    ctx.save();
    ctx.strokeStyle = 'rgba(245, 158, 11, 0.68)';
    ctx.lineWidth = 1.8;
    ctx.setLineDash([5, 6]);
    ctx.lineDashOffset = this.elapsed * 32;

    ctx.beginPath();
    ctx.moveTo(src.x, src.y);
    ctx.quadraticCurveTo(ctrlX, ctrlY, waf.x, waf.y);
    ctx.stroke();

    ctx.setLineDash([]);
    ctx.font = '600 10px "Fira Code", monospace';
    ctx.fillStyle = '#fcd34d';
    ctx.textAlign = 'center';
    ctx.fillText('C2 Egress Beacon (TLS JA3 / T1071)', ctrlX, ctrlY + 14);

    // Expanding C2 beacon pulse ring around Endpoint WS-14 (or Core DB)
    const pulse = (this.elapsed * 1.4) % 1;
    ctx.strokeStyle = `rgba(245, 158, 11, ${(1 - pulse) * 0.65})`;
    ctx.lineWidth = 1.8;
    ctx.beginPath();
    ctx.arc(src.x, src.y, 26 + pulse * 26, 0, Math.PI * 2);
    ctx.stroke();
    ctx.restore();
  }

  private drawNode(
    ctx: CanvasRenderingContext2D,
    node: TopologyNode,
    x: number,
    y: number,
    idx: number
  ): void {
    const isCompromised =
      this.scenario !== 'NONE' &&
      !this.contained &&
      ((this.scenario === 'PHISHING_C2' && (idx === 1 || idx === 3)) ||
        (this.scenario === 'KERBEROAST_SMB' && (idx === 2 || idx === 3 || idx === 4)) ||
        (this.scenario === 'RANSOMWARE_WIPE' && (idx === 3 || idx === 4)));

    const isQuarantined = this.contained && (idx === 3 || idx === 4);

    ctx.save();

    // SOAR Quarantine Ring
    if (isQuarantined) {
      const rot = this.elapsed * 1.2;
      ctx.strokeStyle = '#10b981';
      ctx.lineWidth = 2.4;
      ctx.setLineDash([8, 5]);
      ctx.beginPath();
      ctx.arc(x, y, 36, rot, rot + Math.PI * 2);
      ctx.stroke();
      ctx.setLineDash([]);

      ctx.fillStyle = 'rgba(16, 185, 129, 0.14)';
      ctx.beginPath();
      ctx.arc(x, y, 34, 0, Math.PI * 2);
      ctx.fill();

      ctx.font = '700 9px "Fira Code", monospace';
      ctx.fillStyle = '#6ee7b7';
      ctx.textAlign = 'center';
      ctx.fillText('SOAR QUARANTINE', x, y - 44);
    } else if (isCompromised) {
      const pulse = 0.5 + 0.5 * Math.sin(this.elapsed * 6);
      ctx.strokeStyle = `rgba(244, 63, 94, ${0.45 + pulse * 0.45})`;
      ctx.lineWidth = 2.5;
      ctx.beginPath();
      ctx.arc(x, y, 34, 0, Math.PI * 2);
      ctx.stroke();
    }

    // Node body hex/circle
    const nodeStroke = isQuarantined
      ? '#10b981'
      : isCompromised
        ? '#f43f5e'
        : node.zone === 'CROWN'
          ? '#f59e0b'
          : '#06b6d4';

    ctx.fillStyle = '#091124';
    ctx.strokeStyle = nodeStroke;
    ctx.lineWidth = 2;
    ctx.shadowColor = nodeStroke;
    ctx.shadowBlur = isCompromised ? 16 : 9;

    ctx.beginPath();
    ctx.roundRect(x - 24, y - 24, 48, 48, 12);
    ctx.fill();
    ctx.stroke();
    ctx.shadowBlur = 0;

    // Minimalist vector glyph inside node
    ctx.strokeStyle = nodeStroke;
    ctx.lineWidth = 1.8;
    ctx.beginPath();
    if (node.zone === 'EDGE') {
      // Firewall shield
      ctx.moveTo(x, y - 11);
      ctx.lineTo(x + 10, y - 6);
      ctx.lineTo(x + 10, y + 3);
      ctx.quadraticCurveTo(x, y + 12, x, y + 12);
      ctx.quadraticCurveTo(x, y + 12, x - 10, y + 3);
      ctx.lineTo(x - 10, y - 6);
      ctx.closePath();
    } else if (node.zone === 'DMZ') {
      // Server stack
      ctx.rect(x - 10, y - 9, 20, 7);
      ctx.rect(x - 10, y + 2, 20, 7);
    } else if (node.zone === 'IDENTITY') {
      // AD Key / Directory node
      ctx.arc(x - 3, y - 2, 6, 0, Math.PI * 2);
      ctx.moveTo(x + 3, y - 2);
      ctx.lineTo(x + 11, y - 2);
      ctx.lineTo(x + 11, y + 4);
    } else if (node.zone === 'ENDPOINT') {
      // Terminal monitor
      ctx.rect(x - 11, y - 9, 22, 14);
      ctx.moveTo(x - 5, y + 9);
      ctx.lineTo(x + 5, y + 9);
    } else {
      // Core DB Vault cylinders
      ctx.ellipse(x, y - 7, 10, 4, 0, 0, Math.PI * 2);
      ctx.moveTo(x - 10, y - 7);
      ctx.lineTo(x - 10, y + 7);
      ctx.ellipse(x, y + 7, 10, 4, 0, 0, Math.PI);
      ctx.moveTo(x + 10, y - 7);
      ctx.lineTo(x + 10, y + 7);
    }
    ctx.stroke();

    // Node labels
    ctx.textAlign = 'center';
    ctx.font = '700 11px "Outfit", sans-serif';
    ctx.fillStyle = '#f1f5f9';
    ctx.fillText(node.label, x, y + 40);

    ctx.font = '500 9.5px "Fira Code", monospace';
    ctx.fillStyle = isCompromised ? '#fda4af' : '#94a3b8';
    ctx.fillText(node.ip, x, y + 53);

    ctx.font = '400 9px "Fira Code", monospace';
    ctx.fillStyle = '#64748b';
    ctx.fillText(node.sublabel, x, y + 66);

    ctx.restore();
  }
}
