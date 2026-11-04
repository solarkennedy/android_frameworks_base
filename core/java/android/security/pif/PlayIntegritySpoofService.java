/*
 * Copyright (C) 2024-2026 The Evolution X Project
 * Copyright (C) 2026 The LineageOS Project (pepito port)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package android.security.pif;

import android.content.ContentResolver;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.os.Parcel;
import android.os.Parcelable;
import android.provider.Settings;
import android.util.Base64;
import android.util.JsonReader;
import android.util.Log;

import java.security.Provider;
import java.security.Security;

import java.io.File;
import java.io.StringReader;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-process port of the PlayIntegrityFix ("PIF") mechanism, adapted from
 * Evolution X's framework integration.
 *
 * Only two processes are ever touched:
 *   - com.google.android.gms.unstable (DroidGuard): every Build / Build.VERSION
 *     field listed in the config is reflect-set to the configured value.
 *   - com.android.vending (Play Store): optionally FINGERPRINT and SDK_INT.
 *
 * Config resolution order (first non-empty wins):
 *   1. Settings.Secure "spoof_pif_config"  (adb: settings put secure spoof_pif_config "$(cat pif.json)")
 *   2. /system/etc/pif.json                (shipped by the device tree)
 *
 * Accepted formats: a flat JSON object, or "KEY=value" lines. Keys that name a
 * Build/Build.VERSION field are spoofed; the control keys are:
 *   spoofBuild (1), spoofVendingFinger (0|1|<fingerprint>), spoofVendingSdk (0),
 *   spoofSignature (0), verboseLogs (0), DEBUG (0).
 *
 * Pepito simplifications vs. Evolution X: the config is read directly from the
 * settings provider / a file instead of via a system_server binder round-trip,
 * the system-property part of the upstream config is dropped, and the
 * keystore-provider part is reimplemented in {@link PifKeyStoreProvider}
 * (spoofProvider=1).
 *
 * @hide
 */
public final class PlayIntegritySpoofService {
    private static final String TAG = "PIF";

    public static final String SETTING_KEY = "spoof_pif_config";
    private static final String FALLBACK_FILE = "/system/etc/pif.json";

    private static final String DROIDGUARD_PACKAGE = "com.google.android.gms.unstable";
    private static final String VENDING_PACKAGE = "com.android.vending";
    private static final String GMS_PACKAGE = "com.google.android.gms";

    // Google's "Android" platform signing certificate, as embedded by the PIF module.
    private static final String ROM_SIGNATURE_DATA = "MIIFyTCCA7GgAwIBAgIVALyxxl+zDS9SL68SzOr48309eAZyMA0GCSqGSIb3DQEBCwUAMHQxCzAJ" +
            "BgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRQw" +
            "EgYDVQQKEwtHb29nbGUgSW5jLjEQMA4GA1UECxMHQW5kcm9pZDEQMA4GA1UEAxMHQW5kcm9pZDAg" +
            "Fw0yMjExMDExODExMzVaGA8yMDUyMTEwMTE4MTEzNVowdDELMAkGA1UEBhMCVVMxEzARBgNVBAgT" +
            "CkNhbGlmb3JuaWExFjAUBgNVBAcTDU1vdW50YWluIFZpZXcxFDASBgNVBAoTC0dvb2dsZSBJbmMu" +
            "MRAwDgYDVQQLEwdBbmRyb2lkMRAwDgYDVQQDEwdBbmRyb2lkMIICIjANBgkqhkiG9w0BAQEFAAOC" +
            "Ag8AMIICCgKCAgEAsqtalIy/nctKlrhd1UVoDffFGnDf9GLi0QQhsVoJkfF16vDDydZJOycG7/kQ" +
            "ziRZhFdcoMrIYZzzw0ppBjsSe1AiWMuKXwTBaEtxN99S1xsJiW4/QMI6N6kMunydWRMsbJ6aAxi1" +
            "lVq0bxSwr8Sg/8u9HGVivfdG8OpUM+qjuV5gey5xttNLK3BZDrAlco8RkJZryAD40flmJZrWXJmc" +
            "r2HhJJUnqG4Z3MSziEgW1u1JnnY3f/BFdgYsA54SgdUGdQP3aqzSjIpGK01/vjrXvifHazSANjvl" +
            "0AUE5i6AarMw2biEKB2ySUDp8idC5w12GpqDrhZ/QkW8yBSa87KbkMYXuRA2Gq1fYbQx3YJraw0U" +
            "gZ4M3fFKpt6raxxM5j0sWHlULD7dAZMERvNESVrKG3tQ7B39WAD8QLGYc45DFEGOhKv5Fv8510h5" +
            "sXK502IvGpI4FDwz2rbtAgJ0j+16db5wCSW5ThvNPhCheyciajc8dU1B5tJzZN/ksBpzne4Xf9gO" +
            "LZ9ZU0+3Z5gHVvTS/YpxBFwiFpmL7dvGxew0cXGSsG5UTBlgr7i0SX0WhY4Djjo8IfPwrvvA0QaC" +
            "FamdYXKqBsSHgEyXS9zgGIFPt2jWdhaS+sAa//5SXcWro0OdiKPuwEzLgj759ke1sHRnvO735dYn" +
            "5whVbzlGyLBh3L0CAwEAAaNQME4wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQUU1eXQ7NoYKjvOQlh" +
            "5V8jHQMoxA8wHwYDVR0jBBgwFoAUU1eXQ7NoYKjvOQlh5V8jHQMoxA8wDQYJKoZIhvcNAQELBQAD" +
            "ggIBAHFIazRLs3itnZKllPnboSd6sHbzeJURKehx8GJPvIC+xWlwWyFO5+GHmgc3yh/SVd3Xja/k" +
            "8Ud59WEYTjyJJWTw0Jygx37rHW7VGn2HDuy/x0D+els+S8HeLD1toPFMepjIXJn7nHLhtmzTPlDW" +
            "DrhiaYsls/k5Izf89xYnI4euuOY2+1gsweJqFGfbznqyqy8xLyzoZ6bvBJtgeY+G3i/9Be14HseS" +
            "Na4FvI1Oze/l2gUu1IXzN6DGWR/lxEyt+TncJfBGKbjafYrfSh3zsE4N3TU7BeOL5INirOMjre/j" +
            "VgB1YQG5qLVaPoz6mdn75AbBBm5a5ahApLiKqzy/hP+1rWgw8Ikb7vbUqov/bnY3IlIU6XcPJTCD" +
            "b9aRZQkStvYpQd82XTyxD/T0GgRLnUj5Uv6iZlikFx1KNj0YNS2T3gyvL++J9B0Y6gAkiG0EtNpl" +
            "z7Pomsv5pVdmHVdKMjqWw5/6zYzVmu5cXFtR384Ti1qwML1xkD6TC3VIv88rKIEjrkY2c+v1frh9" +
            "fRJ2OmzXmML9NgHTjEiJR2Ib2iNrMKxkuTIs9oxKZgrJtJKvdU9qJJKM5PnZuNuHhGs6A/9gt9Oc" +
            "cetYeQvVSqeEmQluWfcunQn9C9Vwi2BJIiVJh4IdWZf5/e2PlSSQ9CJjz2bKI17pzdxOmjQfE0JS" +
            "F7Xt";

    private static PlayIntegritySpoofService sInstance;

    private volatile int mVerboseLogs = 0;
    private volatile boolean mSpoofBuild = true;
    private volatile boolean mSpoofSignature = false;
    private volatile String mSpoofVendingFinger = "0";
    private volatile boolean mSpoofVendingSdk = false;
    private volatile boolean mSpoofProvider = false;
    private volatile boolean mDebug = false;

    private final Map<String, String> mBuildFields = new ConcurrentHashMap<>();
    private volatile boolean mConfigLoaded = false;
    private volatile String mConfigSource = "none";
    private volatile boolean mSignatureSpoofed = false;
    private volatile boolean mProviderSpoofed = false;
    private volatile boolean mLoadAttempted = false;

    private PlayIntegritySpoofService() {}

    /** Process-wide singleton; the config is loaded on first use. */
    public static synchronized PlayIntegritySpoofService getInstance() {
        if (sInstance == null) {
            sInstance = new PlayIntegritySpoofService();
        }
        return sInstance;
    }

    /** Load the config at most once per process (used by system_server). */
    public synchronized void loadConfigOnce(ContentResolver resolver) {
        if (mLoadAttempted) return;
        mLoadAttempted = true;
        loadConfig(resolver);
    }

    /**
     * (Re)load the config. Safe to call with a null resolver (file fallback only).
     */
    public void loadConfig(ContentResolver resolver) {
        mBuildFields.clear();
        mConfigLoaded = false;
        mConfigSource = "none";

        String content = null;
        if (resolver != null) {
            try {
                content = Settings.Secure.getString(resolver, SETTING_KEY);
                if (content != null && !content.trim().isEmpty()) {
                    mConfigSource = "settings";
                }
            } catch (Throwable e) {
                Log.w(TAG, "Settings read failed: " + e);
            }
        }
        if (content == null || content.trim().isEmpty()) {
            try {
                File f = new File(FALLBACK_FILE);
                if (f.isFile()) {
                    content = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
                    if (!content.trim().isEmpty()) mConfigSource = FALLBACK_FILE;
                }
            } catch (Throwable e) {
                Log.w(TAG, "File read failed: " + e);
            }
        }
        if (content == null || content.trim().isEmpty()) {
            Log.i(TAG, "No PIF config (settings key '" + SETTING_KEY + "' and "
                    + FALLBACK_FILE + " both empty) - spoofing disabled");
            return;
        }

        try {
            String trimmed = content.trim();
            if (trimmed.startsWith("{")) {
                parseJson(trimmed);
            } else {
                parseProp(trimmed);
            }
            mConfigLoaded = true;
            Log.i(TAG, "PIF config loaded from " + mConfigSource
                    + ", fields=" + mBuildFields.size()
                    + ", spoofBuild=" + mSpoofBuild
                    + ", spoofVendingFinger=" + mSpoofVendingFinger
                    + ", spoofVendingSdk=" + mSpoofVendingSdk
                    + ", spoofSignature=" + mSpoofSignature
                    + ", spoofProvider=" + mSpoofProvider);
        } catch (Throwable e) {
            Log.e(TAG, "Failed to load PIF config", e);
        }
    }

    private void parseProp(String content) {
        for (String raw : content.split("\n")) {
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            int eqIdx = line.indexOf('=');
            if (eqIdx <= 0) continue;
            String key = line.substring(0, eqIdx).trim();
            String value = line.substring(eqIdx + 1).trim();
            int commentIdx = value.indexOf('#');
            if (commentIdx >= 0) value = value.substring(0, commentIdx).trim();
            if (value.isEmpty()) continue;
            processKeyValue(key, value);
        }
    }

    private void parseJson(String content) {
        try (JsonReader reader = new JsonReader(new StringReader(content))) {
            reader.beginObject();
            while (reader.hasNext()) {
                String key = reader.nextName();
                String value;
                switch (reader.peek()) {
                    case BOOLEAN:
                        value = String.valueOf(reader.nextBoolean());
                        break;
                    case NUMBER:
                        value = reader.nextString();
                        break;
                    case NULL:
                        reader.nextNull();
                        continue;
                    case BEGIN_ARRAY:
                    case BEGIN_OBJECT:
                        reader.skipValue();
                        continue;
                    default:
                        value = reader.nextString();
                        break;
                }
                processKeyValue(key, value);
            }
            reader.endObject();
        } catch (Exception e) {
            Log.e(TAG, "Failed to parse JSON config", e);
        }
    }

    private static boolean isTrue(String value) {
        return "1".equals(value) || "true".equalsIgnoreCase(value);
    }

    private void processKeyValue(String key, String value) {
        switch (key) {
            case "verboseLogs":
            case "VERBOSE_LOGS":
                try {
                    mVerboseLogs = Integer.parseInt(value);
                } catch (NumberFormatException e) {
                    mVerboseLogs = 0;
                }
                break;
            case "spoofBuild":
                mSpoofBuild = isTrue(value);
                break;
            case "spoofSignature":
                mSpoofSignature = isTrue(value);
                break;
            case "spoofVendingFinger":
                mSpoofVendingFinger = value;
                break;
            case "spoofVendingBuild":
                if ("0".equals(mSpoofVendingFinger) && isTrue(value)) {
                    mSpoofVendingFinger = "1";
                }
                break;
            case "spoofVendingSdk":
                mSpoofVendingSdk = isTrue(value);
                break;
            case "spoofProvider":
                mSpoofProvider = isTrue(value);
                break;
            case "DEBUG":
                mDebug = isTrue(value);
                break;
            // Upstream config knob with no effect in this port.
            case "spoofProps":
                break;
            default:
                if (key.startsWith("_") || key.contains(".") || key.startsWith("*")
                        || "manually_imported".equals(key)) {
                    // metadata / system-property patterns: ignored
                    break;
                }
                mBuildFields.put(key, value);
                break;
        }
    }

    public boolean shouldSpoof(String processName) {
        if (!mConfigLoaded) return false;
        return DROIDGUARD_PACKAGE.equals(processName) || VENDING_PACKAGE.equals(processName);
    }

    public boolean isTargetProcess(String processName) {
        return DROIDGUARD_PACKAGE.equals(processName) || VENDING_PACKAGE.equals(processName);
    }

    public boolean isDroidGuard(String processName) {
        return DROIDGUARD_PACKAGE.equals(processName);
    }

    public boolean isVending(String processName) {
        return VENDING_PACKAGE.equals(processName);
    }

    public void spoofBuildFields(String processName) {
        if (!mConfigLoaded) return;
        boolean isVending = isVending(processName);
        boolean isDroidGuard = isDroidGuard(processName);
        if (!isDroidGuard && !isVending) return;

        if (isVending) {
            String vendingFingerprint = resolveVendingFingerprint();
            if (vendingFingerprint == null) {
                if (mVerboseLogs > 0) Log.d(TAG, "Vending FINGERPRINT spoofing disabled");
            } else {
                spoofField("FINGERPRINT", vendingFingerprint, "PS");
            }
            if (mSpoofVendingSdk) {
                spoofSdkInt("PS");
            }
            return;
        }

        if (!mSpoofBuild) {
            if (mVerboseLogs > 0) Log.d(TAG, "Build spoofing disabled");
            return;
        }
        for (Map.Entry<String, String> entry : mBuildFields.entrySet()) {
            spoofField(entry.getKey(), entry.getValue(), "DG");
        }
        Log.i(TAG, "Applied " + mBuildFields.size() + " Build fields in DroidGuard process");
    }

    private String resolveVendingFingerprint() {
        String setting = mSpoofVendingFinger;
        if (setting == null || setting.isEmpty()
                || "0".equals(setting) || "false".equalsIgnoreCase(setting)) {
            return null;
        }
        if (isTrue(setting)) {
            return mBuildFields.get("FINGERPRINT");
        }
        return setting;
    }

    public void spoofSignature(String processName) {
        if (isVending(processName)) {
            if (mVerboseLogs > 0) Log.d(TAG, "Signature spoofing skipped for Vending");
            return;
        }
        if (!mSpoofSignature || mSignatureSpoofed) return;

        Signature spoofedSignature = new Signature(Base64.decode(ROM_SIGNATURE_DATA, Base64.DEFAULT));
        Parcelable.Creator<PackageInfo> originalCreator = PackageInfo.CREATOR;
        Parcelable.Creator<PackageInfo> customCreator =
                new CustomPackageInfoCreator(originalCreator, spoofedSignature);

        Field creatorField;
        try {
            creatorField = findField(PackageInfo.class, "CREATOR");
        } catch (Exception e) {
            Log.e(TAG, "Couldn't find PackageInfo.CREATOR: " + e);
            return;
        }
        try {
            creatorField.setAccessible(true);
            creatorField.set(null, customCreator);
        } catch (Exception e) {
            Log.e(TAG, "Couldn't replace PackageInfo.CREATOR: " + e);
            return;
        } finally {
            creatorField.setAccessible(false);
        }

        clearStaticMap(PackageManager.class, "sPackageInfoCache");
        clearStaticMap(Parcel.class, "mCreators");
        clearStaticMap(Parcel.class, "sPairedCreators");

        mSignatureSpoofed = true;
        Log.i(TAG, "Signature spoofing enabled via Parcelable.Creator");
    }

    private void clearStaticMap(Class<?> clazz, String fieldName) {
        try {
            Field f = findField(clazz, fieldName);
            f.setAccessible(true);
            try {
                Object o = f.get(null);
                if (o instanceof Map) {
                    ((Map<?, ?>) o).clear();
                } else if (o != null) {
                    Method clear = o.getClass().getMethod("clear");
                    clear.invoke(o);
                }
            } finally {
                f.setAccessible(false);
            }
        } catch (Exception e) {
            if (mDebug) Log.d(TAG, "Couldn't clear " + clazz.getSimpleName() + "." + fieldName + ": " + e);
        }
    }

    private Field findField(Class<?> clazz, String fieldName) throws NoSuchFieldException {
        Class<?> current = clazz;
        while (current != null && !current.equals(Object.class)) {
            try {
                return current.getDeclaredField(fieldName);
            } catch (NoSuchFieldException e) {
                current = current.getSuperclass();
            }
        }
        throw new NoSuchFieldException("Field '" + fieldName + "' not found");
    }

    private void spoofSdkInt(String logSuffix) {
        String configSdk = mBuildFields.get("SDK_INT");
        int targetSdk;
        try {
            targetSdk = (configSdk != null) ? Integer.parseInt(configSdk) : 32;
        } catch (NumberFormatException e) {
            targetSdk = 32;
        }
        spoofField("SDK_INT", String.valueOf(targetSdk), logSuffix);
    }

    private void spoofField(String fieldName, String value, String logSuffix) {
        if (value == null || value.isEmpty()) {
            if (mVerboseLogs > 0) Log.d(TAG, fieldName + " is empty, skipping");
            return;
        }
        Field field;
        try {
            if (hasField(Build.class, fieldName)) {
                field = Build.class.getDeclaredField(fieldName);
            } else if (hasField(Build.VERSION.class, fieldName)) {
                field = Build.VERSION.class.getDeclaredField(fieldName);
            } else {
                if (mVerboseLogs > 1) Log.d(TAG, "Field not found: " + fieldName);
                return;
            }
        } catch (Exception e) {
            Log.e(TAG, "Failed to locate field " + fieldName, e);
            return;
        }
        field.setAccessible(true);
        try {
            String oldValue = String.valueOf(field.get(null));
            if (value.equals(oldValue)) {
                if (mVerboseLogs > 2) Log.d(TAG, "[" + fieldName + "]: " + value + " (unchanged)");
                return;
            }
            Class<?> fieldType = field.getType();
            Object newValue;
            if (fieldType == String.class) {
                newValue = value;
            } else if (fieldType == int.class) {
                newValue = Integer.parseInt(value);
            } else if (fieldType == long.class) {
                newValue = Long.parseLong(value);
            } else if (fieldType == boolean.class) {
                newValue = Boolean.parseBoolean(value);
            } else {
                Log.w(TAG, "Unsupported field type: " + fieldType + " for " + fieldName);
                return;
            }
            field.set(null, newValue);
            Log.d(TAG + "/Java:" + logSuffix, "[" + fieldName + "]: " + oldValue + " -> " + value);
        } catch (Exception e) {
            Log.e(TAG, "Failed to spoof " + fieldName, e);
        } finally {
            field.setAccessible(false);
        }
    }

    private static boolean hasField(Class<?> clazz, String fieldName) {
        for (Field f : clazz.getDeclaredFields()) {
            if (f.getName().equals(fieldName)) return true;
        }
        return false;
    }

    public boolean isSpoofProviderEnabled() {
        return mSpoofProvider && mConfigLoaded;
    }

    /**
     * Install {@link PifKeyStoreProvider} in place of "AndroidKeyStore" so that
     * hardware key-attestation chains cannot be fetched in this process. Call
     * only from the DroidGuard process, after build fields are spoofed. Idempotent.
     */
    public void spoofProvider() {
        if (!mSpoofProvider || mProviderSpoofed) return;
        try {
            Provider base = Security.getProvider("AndroidKeyStore");
            if (base == null) {
                Log.w(TAG, "AndroidKeyStore provider not found; cannot hide attestation");
                return;
            }
            if (base instanceof PifKeyStoreProvider) {
                mProviderSpoofed = true;
                return;
            }
            Provider custom = new PifKeyStoreProvider(base);
            Security.removeProvider("AndroidKeyStore");
            int pos = Security.insertProviderAt(custom, 1);
            mProviderSpoofed = true;
            Log.i(TAG, "Keystore attestation hidden in DroidGuard (provider inserted at " + pos + ")");
        } catch (Throwable t) {
            Log.e(TAG, "Failed to install PIF keystore provider", t);
        }
    }

    public boolean isSpoofSignatureEnabled() {
        return mSpoofSignature && mConfigLoaded;
    }

    public boolean isConfigLoaded() {
        return mConfigLoaded;
    }

    public String getConfigSource() {
        return mConfigSource;
    }

    public Map<String, String> getBuildFields() {
        return mBuildFields;
    }

    public byte[] getRomSignatureBytes() {
        return Base64.decode(ROM_SIGNATURE_DATA, Base64.DEFAULT);
    }

    public void logBuildFields() {
        if (mVerboseLogs < 100) return;
        for (Field field : Build.class.getDeclaredFields()) {
            try {
                Log.d(TAG, "Build." + field.getName() + " = " + field.get(null));
            } catch (Exception ignored) {
            }
        }
        for (Field field : Build.VERSION.class.getDeclaredFields()) {
            try {
                Log.d(TAG, "Build.VERSION." + field.getName() + " = " + field.get(null));
            } catch (Exception ignored) {
            }
        }
    }

    private static class CustomPackageInfoCreator implements Parcelable.Creator<PackageInfo> {
        private final Parcelable.Creator<PackageInfo> mOriginal;
        private final Signature mSpoofed;

        CustomPackageInfoCreator(Parcelable.Creator<PackageInfo> original, Signature spoofed) {
            mOriginal = original;
            mSpoofed = spoofed;
        }

        @Override
        @SuppressWarnings("deprecation")
        public PackageInfo createFromParcel(Parcel source) {
            PackageInfo packageInfo = mOriginal.createFromParcel(source);
            if ("android".equals(packageInfo.packageName)) {
                if (packageInfo.signatures != null && packageInfo.signatures.length > 0) {
                    packageInfo.signatures[0] = mSpoofed;
                }
                if (packageInfo.signingInfo != null) {
                    Signature[] signers = packageInfo.signingInfo.getApkContentsSigners();
                    if (signers != null && signers.length > 0) {
                        signers[0] = mSpoofed;
                    }
                }
            }
            return packageInfo;
        }

        @Override
        public PackageInfo[] newArray(int size) {
            return mOriginal.newArray(size);
        }
    }
}
