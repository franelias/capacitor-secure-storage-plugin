export type GetOptions = {
  key: string
}

export type SetOptions = {
  key: string
  value: string
}

export type RemoveOptions = {
  key: string
}

export interface SecureStoragePluginPlugin {
  get(options: GetOptions): Promise<{ value: string }>;
  set(options: SetOptions): Promise<{ value: boolean }>;
  remove(options: RemoveOptions): Promise<{ value: boolean }>;
  clear(): Promise<{ value: boolean }>;
  keys(): Promise<{ value: string[] }>;
  getPlatform(): Promise<{ value: string }>;
}
