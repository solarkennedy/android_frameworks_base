/*
 * Copyright (C) 2026 The LineageOS Project (pepito Play Integrity Fix port)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package android.security.pif;

import android.security.keystore2.AndroidKeyStoreSpi;
import android.util.Log;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

/**
 * Drop-in replacement for the "AndroidKeyStore" security provider, installed only
 * inside the DroidGuard process (com.google.android.gms.unstable) when the PIF
 * config sets spoofProvider=1, and inside the Play Store (com.android.vending)
 * when it sets spoofVendingProvider=1.
 *
 * It behaves exactly like the real provider for every operation except one:
 * engineGetCertificateChain refuses to hand back a chain that carries a hardware
 * key-attestation extension. DroidGuard treats that refusal as "hardware
 * attestation unavailable" and falls back to the software evaluation path, so the
 * genuine 2018-era KeyMaster 3 chain is never presented during an integrity
 * request. Nothing is forged: a key with no attestation extension is returned
 * untouched, and no keybox is involved.
 *
 * This is the in-framework equivalent of the PlayIntegrityFix module's
 * "spoofProvider" trick; because we live in the boot classpath we can extend
 * android.security.keystore2.AndroidKeyStoreSpi directly instead of by reflection.
 *
 * @hide
 */
public final class PifKeyStoreProvider extends Provider {

    private static final String TAG = "PIF";

    /** Android Key Attestation certificate extension OID. */
    private static final String ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";

    public PifKeyStoreProvider(Provider base) {
        super(base.getName(), base.getVersion(), base.getInfo());
        // Copy every service (KeyStore, KeyPairGenerator, ...) from the real
        // provider so only KeyStore/AndroidKeyStore is intercepted below.
        putAll(base);
    }

    @Override
    public synchronized Service getService(String type, String algorithm) {
        final Service service = super.getService(type, algorithm);
        if (service != null
                && "KeyStore".equals(type)
                && AndroidKeyStoreSpi.NAME.equals(algorithm)) {
            return new PifKeyStoreService(service);
        }
        return service;
    }

    private static final class PifKeyStoreService extends Service {
        PifKeyStoreService(Service base) {
            super(base.getProvider(), base.getType(), base.getAlgorithm(),
                    base.getClassName(), null /* aliases */, null /* attributes */);
        }

        @Override
        public Object newInstance(Object constructorParameter) throws NoSuchAlgorithmException {
            return new PifKeyStoreSpi();
        }
    }

    private static final class PifKeyStoreSpi extends AndroidKeyStoreSpi {
        @Override
        public Certificate[] engineGetCertificateChain(String alias) {
            final Certificate[] chain = super.engineGetCertificateChain(alias);
            if (chain != null && chain.length > 0 && chain[0] instanceof X509Certificate) {
                final X509Certificate leaf = (X509Certificate) chain[0];
                if (leaf.getExtensionValue(ATTESTATION_OID) != null) {
                    Log.i(TAG, "Hiding hardware attestation chain for alias '" + alias + "'");
                    throw new UnsupportedOperationException(
                            "PIF: hardware attestation unavailable");
                }
            }
            return chain;
        }
    }
}
