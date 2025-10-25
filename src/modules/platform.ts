/**
 * Platform Detection Module
 * Detects the operating system and maps it to the correct script path
 */

import * as path from 'path';
import { Platform } from '../types';

export class PlatformDetector {
  /**
   * Detect the current operating system platform
   * @returns Platform identifier ('windows', 'linux', or 'darwin')
   */
  static detectPlatform(): Platform {
    const platform = process.platform;

    switch (platform) {
      case 'win32':
        return 'windows';
      case 'linux':
        return 'linux';
      case 'darwin':
        return 'darwin';
      default:
        throw new Error(`Unsupported platform: ${platform}`);
    }
  }

  /**
   * Get the script directory path for the current platform
   * @param rootDir Root directory of the First-On-Scene installation
   * @returns Absolute path to the platform-specific script directory
   */
  static getScriptDirectory(rootDir: string): string {
    const platform = this.detectPlatform();

    switch (platform) {
      case 'windows':
        return path.join(rootDir, 'scripts', 'win');
      case 'linux':
      case 'darwin':
        return path.join(rootDir, 'scripts', 'nix');
      default:
        throw new Error(`No script directory mapped for platform: ${platform}`);
    }
  }

  /**
   * Get the appropriate shell executable for the current platform
   * @returns Shell executable path/command
   */
  static getShellExecutable(): string {
    const platform = this.detectPlatform();

    switch (platform) {
      case 'windows':
        return 'powershell.exe';
      case 'linux':
      case 'darwin':
        return '/bin/bash';
      default:
        throw new Error(`No shell executable mapped for platform: ${platform}`);
    }
  }

  /**
   * Get the main data collection script name for the current platform
   * @returns Script filename
   */
  static getCollectionScriptName(): string {
    const platform = this.detectPlatform();

    switch (platform) {
      case 'windows':
        return 'Gather_Info.ps1';
      case 'linux':
      case 'darwin':
        return 'gather_info.sh';
      default:
        throw new Error(`No collection script defined for platform: ${platform}`);
    }
  }

  /**
   * Check if the current platform is supported
   * @returns true if platform is supported, false otherwise
   */
  static isPlatformSupported(): boolean {
    try {
      this.detectPlatform();
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Get human-readable platform name
   * @returns Platform display name
   */
  static getPlatformDisplayName(): string {
    const platform = this.detectPlatform();

    switch (platform) {
      case 'windows':
        return 'Windows';
      case 'linux':
        return 'Linux';
      case 'darwin':
        return 'macOS';
      default:
        return 'Unknown';
    }
  }
}
