package com.whitestein.securestorage;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.x500.X500Principal;


public class PasswordStorageHelper {

    private static final String LOG_TAG = PasswordStorageHelper.class.getSimpleName();
    private static final String PREFERENCES_FILE = "cap_sec";

    private PasswordStorageImpl passwordStorage = null;

    public boolean isInitialized = false;

    public PasswordStorageHelper(Context context) {
        if (android.os.Build.VERSION.SDK_INT < 18) {
            passwordStorage = new PasswordStorageHelper_SDK16();
        } else {
            passwordStorage = new PasswordStorageHelper_SDK18();
        }

        try {
            isInitialized = passwordStorage.init(context);
        } catch (Exception ex) {
            Log.e(LOG_TAG, "PasswordStorage initialisation error:" + ex.getMessage(), ex);
        }

        if (!isInitialized && passwordStorage instanceof PasswordStorageHelper_SDK18) {
            passwordStorage = new PasswordStorageHelper_SDK16();
            passwordStorage.init(context);
        }
    }

    public void setData(String key, byte[] data) throws Exception {
        checkInitialized();

        passwordStorage.setData(key, data);
    }

    public byte[] getData(String key) throws Exception {
        checkInitialized();

        return passwordStorage.getData(key);
    }

    public String[] keys() throws Exception{
        checkInitialized();
        return passwordStorage.keys();
    }

    public void remove(String key) throws Exception{
        checkInitialized();
        passwordStorage.remove(key);
    }

    public void clear() throws Exception {
        checkInitialized();
        passwordStorage.clear();
    }

    private void checkInitialized() throws Exception {
        if (!isInitialized) {
            throw new Exception("KeyStore not initialized");
        }
    }

    private interface PasswordStorageImpl {
        boolean init(Context context);

        void setData(String key, byte[] data) throws Exception;

        byte[] getData(String key) throws Exception;

        String[] keys() throws Exception;

        void remove(String key) throws Exception;

        void clear() throws Exception;
    }

    private static class PasswordStorageHelper_SDK16 implements PasswordStorageImpl {
        private SharedPreferences preferences;

        @Override
        public boolean init(Context context) {
            preferences = context.getSharedPreferences(PREFERENCES_FILE, Context.MODE_PRIVATE);
            return true;
        }

        @Override
        public void setData(String key, byte[] data) {
            if (data == null)
                return;
            Editor editor = preferences.edit();
            editor.putString(key, Base64.encodeToString(data, Base64.DEFAULT));
            editor.apply();
        }

        @Override
        public byte[] getData(String key) {
            String res = preferences.getString(key, null);
            if (res == null)
                return null;
            return Base64.decode(res, Base64.DEFAULT);
        }

        @Override
        public String[] keys() {
            Set<String> keySet = preferences.getAll().keySet();
            return keySet.toArray(new String[0]);
        }

        @Override
        public void remove(String key) {
            Editor editor = preferences.edit();
            editor.remove(key);
            editor.apply();
        }

        @Override
        public void clear() {
            Editor editor = preferences.edit();
            editor.clear();
            editor.apply();
        }
    }

    private static class PasswordStorageHelper_SDK18 implements PasswordStorageImpl {
        private static final String KEY_ALGORITHM_RSA = "RSA";

        private static final String KEYSTORE_PROVIDER_ANDROID_KEYSTORE = "AndroidKeyStore";
        private static final String RSA_ECB_PKCS1_PADDING = "RSA/ECB/PKCS1Padding";

        private SharedPreferences preferences;
        private String alias = null;

        @Override
        public boolean init(Context context) {
            preferences = context.getSharedPreferences(PREFERENCES_FILE, Context.MODE_PRIVATE);
            alias = context.getPackageName() + "_cap_sec";

            KeyStore ks;

            try {
                ks = KeyStore.getInstance(KEYSTORE_PROVIDER_ANDROID_KEYSTORE);

                //Use null to load Keystore with default parameters.
                ks.load(null);

                // Check if Private and Public already keys exists. If so we don't need to generate them again
                PrivateKey privateKey = (PrivateKey) ks.getKey(alias, null);
                if (privateKey != null && ks.getCertificate(alias) != null) {
                    PublicKey publicKey = ks.getCertificate(alias).getPublicKey();
                    if (publicKey != null) {
                        // All keys are available.
                        return true;
                    }
                }
            } catch (Exception ex) {
                Log.e(LOG_TAG, "Error retrieving private/public keys from KeyStore", ex);
                return false;
            }

            // Create a start and end time, for the validity range of the key pair that's about to be
            // generated.
            Calendar start = new GregorianCalendar();
            Calendar end = new GregorianCalendar();
            end.add(Calendar.YEAR, 10);

            // Specify the parameters object which will be passed to KeyPairGenerator
            AlgorithmParameterSpec spec;
            if (android.os.Build.VERSION.SDK_INT < 23) {
                spec = new android.security.KeyPairGeneratorSpec.Builder(context)
                        // Alias - is a key for your KeyPair, to obtain it from Keystore in future.
                        .setAlias(alias)
                        // The subject used for the self-signed certificate of the generated pair
                        .setSubject(new X500Principal("CN=" + alias))
                        // The serial number used for the self-signed certificate of the generated pair.
                        .setSerialNumber(BigInteger.valueOf(1337))
                        // Date range of validity for the generated pair.
                        .setStartDate(start.getTime()).setEndDate(end.getTime())
                        .build();
            } else {
                spec = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_DECRYPT)
                        .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                        .build();
            }

            // Initialize a KeyPair generator using the the intended algorithm (in this example, RSA
            // and the KeyStore). This example uses the AndroidKeyStore.
            KeyPairGenerator kpGenerator;
            try {
                kpGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM_RSA, KEYSTORE_PROVIDER_ANDROID_KEYSTORE);
                kpGenerator.initialize(spec);
                // Generate private/public keys
                kpGenerator.generateKeyPair();
            } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchProviderException e) {
                Log.e(LOG_TAG, "Error creating private/public keys", e);
                return false;
            }

            // Check if device support Hardware-backed keystore
            try {
                boolean isInsideSecureHardware = false;
                if (android.os.Build.VERSION.SDK_INT >23) {
                    PrivateKey privateKey = (PrivateKey) ks.getKey(alias, null);
                    KeyFactory keyFactory = KeyFactory.getInstance(privateKey.getAlgorithm(), "AndroidKeyStore");
                    KeyInfo keyInfo = keyFactory.getKeySpec(privateKey, KeyInfo.class);
                    isInsideSecureHardware = keyInfo.isInsideSecureHardware();
                }
                Log.d(LOG_TAG, "Hardware-Backed Keystore Supported: " + isInsideSecureHardware);
            } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | InvalidKeySpecException | NoSuchProviderException ignored) {
            }

            return true;
        }

        @Override
        public void setData(String key, byte[] data) throws Exception {
            KeyStore ks = null;
            ks = KeyStore.getInstance(KEYSTORE_PROVIDER_ANDROID_KEYSTORE);

            ks.load(null);
            if (ks.getCertificate(alias) == null) return;

            PublicKey publicKey = ks.getCertificate(alias).getPublicKey();

            if (publicKey == null) {
                Log.d(LOG_TAG, "Error: Public key was not found in Keystore");
                return;
            }

            String value = encrypt(publicKey, data);

            Editor editor = preferences.edit();
            editor.putString(key, value);
            editor.apply();

        }

        @Override
        public byte[] getData(String key) throws Exception {
            KeyStore ks = null;
            ks = KeyStore.getInstance(KEYSTORE_PROVIDER_ANDROID_KEYSTORE);
            ks.load(null);
            PrivateKey privateKey = (PrivateKey) ks.getKey(alias, null);
            return decrypt(privateKey, preferences.getString(key, null));
        }

        @Override
        public String[] keys() {
            Set<String> keySet = preferences.getAll().keySet();
            return keySet.toArray(new String[0]);
        }

        @Override
        public void remove(String key) {
            Editor editor = preferences.edit();
            editor.remove(key);
            editor.apply();
        }

        @Override
        public void clear() {
            Editor editor = preferences.edit();
            editor.clear();
            editor.apply();
        }

        private static final int KEY_LENGTH = 2048;

        @SuppressLint("TrulyRandom")
        private static String encrypt(PublicKey encryptionKey, byte[] data) throws NoSuchAlgorithmException,
                NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
                NoSuchProviderException, InvalidKeySpecException {

            if (data.length <= KEY_LENGTH / 8 - 11) {
                Cipher cipher = Cipher.getInstance(RSA_ECB_PKCS1_PADDING);
                cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
                byte[] encrypted = cipher.doFinal(data);
                return Base64.encodeToString(encrypted, Base64.DEFAULT);
            } else {
                Cipher cipher = Cipher.getInstance(RSA_ECB_PKCS1_PADDING);
                cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
                int limit = KEY_LENGTH / 8 - 11;
                int position = 0;
                ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                while (position < data.length) {
                    if (data.length - position < limit)
                        limit = data.length - position;
                    byte[] tmpData = cipher.doFinal(data, position, limit);
                    try {
                        byteArrayOutputStream.write(tmpData);
                    } catch (IOException e) {
                        Log.e(LOG_TAG,"error on encrypt write", e);
                    }
                    position += limit;
                }

                return Base64.encodeToString(byteArrayOutputStream.toByteArray(), Base64.DEFAULT);
            }
        }

        private static byte[] decrypt(PrivateKey decryptionKey, String encryptedData) throws NoSuchAlgorithmException,
                NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
                NoSuchProviderException {
            if (encryptedData == null)
                return null;
            byte[] encryptedBuffer = Base64.decode(encryptedData, Base64.DEFAULT);

            if (encryptedBuffer.length <= KEY_LENGTH / 8) {
                Cipher cipher = Cipher.getInstance(RSA_ECB_PKCS1_PADDING);
                cipher.init(Cipher.DECRYPT_MODE, decryptionKey);
                return cipher.doFinal(encryptedBuffer);
            } else {
                Cipher cipher = Cipher.getInstance(RSA_ECB_PKCS1_PADDING);
                cipher.init(Cipher.DECRYPT_MODE, decryptionKey);
                int limit = KEY_LENGTH / 8;
                int position = 0;
                ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                while (position < encryptedBuffer.length) {
                    if (encryptedBuffer.length - position < limit)
                        limit = encryptedBuffer.length - position;
                    byte[] tmpData = cipher.doFinal(encryptedBuffer, position, limit);
                    try {
                        byteArrayOutputStream.write(tmpData);
                    } catch (IOException e) {
                        Log.e(LOG_TAG,"error on decrypt write", e);
                    }
                    position += limit;
                }

                return byteArrayOutputStream.toByteArray();
            }
        }
    }
}
