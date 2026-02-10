export { init } from './init';
export { scan, type ScanFinding, type ScanOptions } from './scan';
export { status, type StatusResult } from './status';
export { verify, type VerifyResult } from './verify';
export { detectAITools, toolDisplayName, type AITool } from './detect';
export { CREDENTIAL_PATTERNS, SECRET_FILE_PATTERNS, CONFIG_FILES, type CredentialPattern } from './patterns';
export { cleanTranscripts, discoverTranscripts, type CleanResult, type CleanOptions, type TranscriptFinding } from './transcript';
export { startWatch, stopWatch, isWatchRunning } from './watch';
