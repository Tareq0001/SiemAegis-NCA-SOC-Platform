/**
 * SIEM-AEGIS: Web Audio API SOC Telemetry & SOAR Containment Soundscape
 * Lead Architect: أ. طارق ابوعشي | Tareq Abuashi — Cybersecurity & Distributed Systems Architect
 */

export class SocAudioEngine {
  private ctx: AudioContext | null = null;
  private enabled = true;
  private lastTickMs = 0;

  private ensureContext(): AudioContext | null {
    if (!this.enabled) return null;
    if (!this.ctx && typeof window !== 'undefined') {
      const AudioCtx =
        window.AudioContext ||
        (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext;
      if (AudioCtx) {
        this.ctx = new AudioCtx();
      }
    }
    if (this.ctx && this.ctx.state === 'suspended') {
      this.ctx.resume().catch(() => {});
    }
    return this.ctx;
  }

  public isEnabled(): boolean {
    return this.enabled;
  }

  public toggle(): boolean {
    this.enabled = !this.enabled;
    return this.enabled;
  }

  /** Subtle telemetry pulse for correlated SIEM log ingestion */
  public playTelemetryTick(severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW'): void {
    const nowMs = performance.now();
    const minInterval = severity === 'CRITICAL' || severity === 'HIGH' ? 140 : 320;
    if (nowMs - this.lastTickMs < minInterval) return;
    this.lastTickMs = nowMs;

    const ctx = this.ensureContext();
    if (!ctx) return;

    const now = ctx.currentTime;
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();

    const baseFreq =
      severity === 'CRITICAL' ? 920 : severity === 'HIGH' ? 760 : severity === 'MEDIUM' ? 620 : 480;
    osc.type = severity === 'CRITICAL' ? 'sawtooth' : 'sine';
    osc.frequency.setValueAtTime(baseFreq, now);
    osc.frequency.exponentialRampToValueAtTime(baseFreq * 0.65, now + 0.045);

    const vol = severity === 'CRITICAL' ? 0.024 : severity === 'HIGH' ? 0.018 : 0.009;
    gain.gain.setValueAtTime(vol, now);
    gain.gain.exponentialRampToValueAtTime(0.0005, now + 0.05);

    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.start(now);
    osc.stop(now + 0.055);
  }

  /** Soft dual-tone SOC alert when an attack scenario is injected */
  public playSocAlert(): void {
    const ctx = this.ensureContext();
    if (!ctx) return;
    const now = ctx.currentTime;

    [540, 720, 540].forEach((freq, idx) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'triangle';
      osc.frequency.setValueAtTime(freq, now + idx * 0.09);

      gain.gain.setValueAtTime(0.042, now + idx * 0.09);
      gain.gain.exponentialRampToValueAtTime(0.0008, now + idx * 0.09 + 0.12);

      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start(now + idx * 0.09);
      osc.stop(now + idx * 0.09 + 0.13);
    });
  }

  /** Ascending harmonic chime when SOAR containment isolates host and restores compliance */
  public playSoarContainment(): void {
    const ctx = this.ensureContext();
    if (!ctx) return;
    const now = ctx.currentTime;

    [523.25, 659.25, 783.99, 1046.5].forEach((freq, idx) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(freq, now + idx * 0.065);

      gain.gain.setValueAtTime(0.04, now + idx * 0.065);
      gain.gain.exponentialRampToValueAtTime(0.0008, now + idx * 0.065 + 0.16);

      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start(now + idx * 0.065);
      osc.stop(now + idx * 0.065 + 0.17);
    });
  }

  /** Crisp UI confirmation tone for baseline reset or technique inspection */
  public playUiConfirm(): void {
    const ctx = this.ensureContext();
    if (!ctx) return;
    const now = ctx.currentTime;

    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = 'sine';
    osc.frequency.setValueAtTime(660, now);
    osc.frequency.exponentialRampToValueAtTime(880, now + 0.06);

    gain.gain.setValueAtTime(0.025, now);
    gain.gain.exponentialRampToValueAtTime(0.0008, now + 0.07);

    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.start(now);
    osc.stop(now + 0.075);
  }
}
