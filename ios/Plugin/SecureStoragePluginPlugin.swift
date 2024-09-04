import Foundation
import Capacitor
import SwiftKeychainWrapper
import KeychainSwift

/**
 * Please read the Capacitor iOS Plugin Development Guide
 * here: https://capacitor.ionicframework.com/docs/plugins/ios
 */
@objc(SecureStoragePlugin)
public class SecureStoragePlugin: CAPPlugin {
    var keychainwrapper: KeychainWrapper = KeychainWrapper.init(serviceName: "cap_sec")
    let keychain = KeychainSwift(keyPrefix: "cap_sec")
    
    @objc func set(_ call: CAPPluginCall) {
        let key = call.getString("key") ?? ""
        let value = call.getString("value") ?? ""
        
        let saveSuccessful = keychain.set(value, forKey: key , withAccess: KeychainSwiftAccessOptions.accessibleAfterFirstUnlock)
        
        if(saveSuccessful) {
            call.resolve([
                "value": saveSuccessful
            ])
        }
        else {
            if #available(iOS 15.0, *) {
                call.reject("error on set", keychain.lastResultCode.formatted())
            } else {
                call.reject("error on set", keychain.lastResultCode.description)
            }
        }
    }
    
    @objc func get(_ call: CAPPluginCall) {
        let key = call.getString("key") ?? ""
        let hasValueDedicated = keychainwrapper.hasValue(forKey: key)
        
        var valueNewKeychain = keychain.get(key)
        let hasValueNewKeychain = valueNewKeychain != nil
        
        if (hasValueDedicated && !hasValueNewKeychain) {
            valueNewKeychain = keychainwrapper.string(forKey: key) ?? ""
            let saveSuccessful = keychain.set(valueNewKeychain ?? "", forKey: key , withAccess: KeychainSwiftAccessOptions.accessibleAfterFirstUnlock)
            
            let removeDedicatedSuccessful: Bool = keychainwrapper.removeObject(forKey: key)

            if (!saveSuccessful || !removeDedicatedSuccessful) {
                call.reject("error")
                return
            }
        }
        
        if (valueNewKeychain != nil) {
            call.resolve([
                "value": valueNewKeychain ?? ""
            ])
            return;
        }
        
        call.reject("Item with given key does not exist")
    }
    
    @objc func keys(_ call: CAPPluginCall) {
        let keys = keychain.allKeys.map { t in t.hasPrefix("cap_sec") ? String(t.dropFirst("cap_sec".count)) : t }

        call.resolve([
            "value": keys
        ])
    }
    
    @objc func remove(_ call: CAPPluginCall) {
        let key = call.getString("key") ?? ""
        let hasValueDedicated = keychainwrapper.hasValue(forKey: key)
        
        let valueNewKeychain = keychain.get(key)
        let hasValueNewKeychain = valueNewKeychain != nil
        
        if(hasValueDedicated || hasValueNewKeychain) {
            keychainwrapper.removeObject(forKey: key);
            let removeDedicatedSuccessful: Bool = keychain.delete(key)
            if(removeDedicatedSuccessful) {
                call.resolve([
                    "value": removeDedicatedSuccessful
                ])
                return;
            }
            
            call.reject("Remove failed")
            return;
        }
        
        call.reject("Item with given key does not exist")
    }
    
    @objc func clear(_ call: CAPPluginCall) {
        let keys = keychain.allKeys.map { t in t.hasPrefix("cap_sec") ? String(t.dropFirst("cap_sec".count)) : t }
        for key in keys {
            keychainwrapper.removeObject(forKey: key)
            keychain.delete(key)

        }
        
        call.resolve([
            "value":  true
        ])
    }
    
    @objc func getPlatform(_ call: CAPPluginCall) {
        call.resolve([
            "value": "ios"
        ])
    }
}
