/**
 * OdinForge Sound Effects System
 *
 * Provides optional cyber-themed UI sounds for enhanced user experience.
 * Sounds are disabled by default and can be enabled in user settings.
 */

type SoundType =
  | "click"
  | "success"
  | "error"
  | "warning"
  | "scan"
  | "notification"
  | "startup"
  | "shutdown";

// Sound configuration
const sounds: Record<SoundType, {
  frequency: number;
  duration: number;
  type: OscillatorType;
  volume?: number;
}> = {
  click: { frequency: 800, duration: 50, type: "sine", volume: 0.1 },
  success: { frequency: 1200, duration: 100, type: "sine", volume: 0.15 },
  error: { frequency: 400, duration: 150, type: "square", volume: 0.2 },
  warning: { frequency: 600, duration: 100, type: "triangle", volume: 0.15 },
  scan: { frequency: 1000, duration: 200, type: "sawtooth", volume: 0.1 },
  notification: { frequency: 880, duration: 80, type: "sine", volume: 0.12 },
  startup: { frequency: 440, duration: 300, type: "sine", volume: 0.15 },
  shutdown: { frequency: 220, duration: 300, type: "sine", volume: 0.15 },
};

class SoundManager {
  private enabled: boolean = false;
  private audioContext: AudioContext | null = null;
  private masterVolume: number = 0.3;

  constructor() {
    // Check localStorage for user preference
    const savedPreference = localStorage.getItem("odinforge-sounds-enabled");
    this.enabled = savedPreference === "true";
  }

  private getAudioContext(): AudioContext {
    if (!this.audioContext) {
      this.audioContext = new (window.AudioContext || (window as any).webkitAudioContext)();
    }
    return this.audioContext;
  }

  setEnabled(enabled: boolean) {
    this.enabled = enabled;
    localStorage.setItem("odinforge-sounds-enabled", enabled.toString());
  }

  isEnabled(): boolean {
    return this.enabled;
  }

  setVolume(volume: number) {
    this.masterVolume = Math.max(0, Math.min(1, volume));
  }

  play(soundType: SoundType) {
    if (!this.enabled) return;

    try {
      const ctx = this.getAudioContext();
      const sound = sounds[soundType];

      // Create oscillator
      const oscillator = ctx.createOscillator();
      const gainNode = ctx.createGain();

      oscillator.type = sound.type;
      oscillator.frequency.value = sound.frequency;

      // Set volume
      const volume = (sound.volume ?? 0.15) * this.masterVolume;
      gainNode.gain.setValueAtTime(volume, ctx.currentTime);
      gainNode.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + sound.duration / 1000);

      // Connect and play
      oscillator.connect(gainNode);
      gainNode.connect(ctx.destination);

      oscillator.start(ctx.currentTime);
      oscillator.stop(ctx.currentTime + sound.duration / 1000);
    } catch (error) {
      console.warn("Failed to play sound:", error);
    }
  }

  // Play a custom frequency sweep (useful for scan effects)
  playSweep(startFreq: number, endFreq: number, duration: number) {
    if (!this.enabled) return;

    try {
      const ctx = this.getAudioContext();
      const oscillator = ctx.createOscillator();
      const gainNode = ctx.createGain();

      oscillator.type = "sine";
      oscillator.frequency.setValueAtTime(startFreq, ctx.currentTime);
      oscillator.frequency.exponentialRampToValueAtTime(endFreq, ctx.currentTime + duration / 1000);

      gainNode.gain.setValueAtTime(0.1 * this.masterVolume, ctx.currentTime);
      gainNode.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + duration / 1000);

      oscillator.connect(gainNode);
      gainNode.connect(ctx.destination);

      oscillator.start(ctx.currentTime);
      oscillator.stop(ctx.currentTime + duration / 1000);
    } catch (error) {
      console.warn("Failed to play sweep:", error);
    }
  }
}

// Singleton instance
export const soundManager = new SoundManager();

// Convenient hooks for React components
export function useSound() {
  return {
    play: (soundType: SoundType) => soundManager.play(soundType),
    playSweep: (startFreq: number, endFreq: number, duration: number) =>
      soundManager.playSweep(startFreq, endFreq, duration),
    setEnabled: (enabled: boolean) => soundManager.setEnabled(enabled),
    isEnabled: () => soundManager.isEnabled(),
    setVolume: (volume: number) => soundManager.setVolume(volume),
  };
}

// Example usage in components:
// const sound = useSound();
// sound.play("click"); // Play on button click
// sound.play("success"); // Play on successful operation
// sound.playSweep(1000, 2000, 500); // Play frequency sweep
