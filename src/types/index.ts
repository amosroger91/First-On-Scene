/**
 * TypeScript type definitions for First-On-Scene forensic artifacts
 * These types correspond to the JSON schema defined in schemas/artifact_schema.json
 */

export type Platform = 'windows' | 'linux' | 'darwin';
export type ExecutionMode = 'local' | 'remote';

export interface CollectionError {
  component: string;
  message: string;
  timestamp?: string;
}

export interface ArtifactMetadata {
  collectionTimestamp: string;
  targetHostname: string;
  platform: Platform;
  collectorVersion: string;
  executionMode?: ExecutionMode;
  errors?: CollectionError[];
}

export interface RegistryRunKey {
  hive: string;
  keyPath: string;
  valueName: string;
  valueData: string;
}

export interface ScheduledTask {
  taskName: string;
  state: string;
  enabled?: boolean;
  author?: string;
  actions?: string;
  triggers?: string;
}

export interface ServiceInfo {
  name: string;
  displayName?: string;
  state: string;
  startMode: string;
  pathName?: string;
}

export interface WMIEventSubscriptions {
  eventFilters?: unknown[];
  eventConsumers?: unknown[];
  filterBindings?: unknown[];
}

export interface CronJob {
  user?: string;
  schedule?: string;
  command?: string;
}

export interface SystemdService {
  unit?: string;
  state?: string;
  enabled?: boolean;
  execStart?: string;
}

export interface PersistenceArtifacts {
  registryRunKeys?: RegistryRunKey[];
  scheduledTasks?: ScheduledTask[];
  services?: ServiceInfo[];
  wmiEventSubscriptions?: WMIEventSubscriptions;
  cronJobs?: CronJob[];
  systemdServices?: SystemdService[];
}

export interface ProcessInfo {
  processId: number;
  name: string;
  executablePath?: string;
  commandLine?: string;
  parentProcessId?: number;
  user?: string;
}

export interface ProcessCreationEvent {
  eventId?: number;
  timestamp?: string;
  newProcessName?: string;
  commandLine?: string;
  parentProcessName?: string;
  user?: string;
}

export interface ExecutionArtifacts {
  processes?: ProcessInfo[];
  processCreationEvents?: ProcessCreationEvent[];
}

export interface NetworkConnection {
  protocol: string;
  localAddress: string;
  localPort: number;
  remoteAddress?: string;
  remotePort?: number;
  state: string;
  processId?: number;
  processName?: string;
}

export interface NetworkArtifacts {
  connections?: NetworkConnection[];
}

export interface LogonEvent {
  eventId?: number;
  timestamp?: string;
  logonType?: number;
  targetUser?: string;
  sourceAddress?: string;
}

export interface PrivilegeEscalationEvent {
  eventId?: number;
  timestamp?: string;
  user?: string;
  privileges?: string;
}

export interface CredentialAccessArtifacts {
  logonEvents?: LogonEvent[];
  privilegeEscalationEvents?: PrivilegeEscalationEvent[];
}

export interface FileMetadata {
  filePath: string;
  created?: string;
  modified?: string;
  accessed?: string;
  entryModified?: string;
  size?: number;
  hash?: string;
}

export interface BrowserArtifacts {
  historyFiles?: string[];
  downloadFiles?: string[];
  cookieFiles?: string[];
}

export interface FileSystemArtifacts {
  fileMetadata?: FileMetadata[];
  browserArtifacts?: BrowserArtifacts;
}

export interface ScriptBlockLog {
  timestamp?: string;
  scriptBlock?: string;
  path?: string;
}

export interface PowerShellActivity {
  scriptBlockLogs?: ScriptBlockLog[];
}

export interface AntivirusScanResult {
  executed: boolean;
  threatsFound?: number;
  scanLog?: string;
}

export interface RkillExecution {
  executed: boolean;
  log?: string;
}

export interface AntivirusScans {
  defenderScan?: AntivirusScanResult;
  clamavScan?: AntivirusScanResult;
  rkillExecution?: RkillExecution;
}

export interface ForensicArtifacts {
  persistence?: PersistenceArtifacts;
  execution?: ExecutionArtifacts;
  network?: NetworkArtifacts;
  credentialAccess?: CredentialAccessArtifacts;
  fileSystem?: FileSystemArtifacts;
  powerShellActivity?: PowerShellActivity;
  antivirusScans?: AntivirusScans;
}

export interface CollectionOutput {
  metadata: ArtifactMetadata;
  artifacts: ForensicArtifacts;
}
