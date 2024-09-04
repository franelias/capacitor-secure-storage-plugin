export declare type GetOptions = {
    key: string;
};
export declare type SetOptions = {
    key: string;
    value: string;
};
export declare type RemoveOptions = {
    key: string;
};
export interface SecureStoragePluginPlugin {
    get(options: GetOptions): Promise<{
        value: string;
    }>;
    set(options: SetOptions): Promise<{
        value: boolean;
    }>;
    remove(options: RemoveOptions): Promise<{
        value: boolean;
    }>;
    clear(): Promise<{
        value: boolean;
    }>;
    keys(): Promise<{
        value: string[];
    }>;
    getPlatform(): Promise<{
        value: string;
    }>;
}
