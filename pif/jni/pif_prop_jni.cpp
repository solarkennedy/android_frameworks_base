/*
 * Copyright (C) 2026 The LineageOS Project
 *
 * JNI bridge from android.security.pif.PlayIntegritySpoofService to the
 * process-local system-property overrides in bionic
 * (__system_property_override_add / _clear, LIBC_PLATFORM). Loaded via
 * System.loadLibrary only inside the DroidGuard process by the framework Play
 * Integrity hook, so the overrides never touch any other process. No hooking,
 * no writable code: the override check is compiled into libc and reads a
 * process-local table.
 *
 * The libc setters are LIBC_PLATFORM symbols, absent from the NDK/apex libc
 * stub this module links against, so they are resolved at runtime with
 * dlsym(RTLD_DEFAULT) rather than at link time. If the running libc predates
 * the override patch, dlsym fails and the calls become no-ops.
 */

#define LOG_TAG "PIF-prop"
#include <android/log.h>
#include <dlfcn.h>
#include <jni.h>

typedef void (*override_add_fn)(const char*, const char*);
typedef void (*override_clear_fn)();

static override_add_fn g_add = nullptr;
static override_clear_fn g_clear = nullptr;

static void nativeAddProp(JNIEnv* env, jclass, jstring jname, jstring jvalue) {
    if (g_add == nullptr || jname == nullptr || jvalue == nullptr) return;
    const char* name = env->GetStringUTFChars(jname, nullptr);
    const char* value = env->GetStringUTFChars(jvalue, nullptr);
    if (name != nullptr && value != nullptr) {
        g_add(name, value);
    }
    if (name != nullptr) env->ReleaseStringUTFChars(jname, name);
    if (value != nullptr) env->ReleaseStringUTFChars(jvalue, value);
}

static void nativeClearProps(JNIEnv*, jclass) {
    if (g_clear != nullptr) g_clear();
}

static const JNINativeMethod kMethods[] = {
    {"nativeAddProp", "(Ljava/lang/String;Ljava/lang/String;)V",
     reinterpret_cast<void*>(nativeAddProp)},
    {"nativeClearProps", "()V", reinterpret_cast<void*>(nativeClearProps)},
};

extern "C" JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    g_add = reinterpret_cast<override_add_fn>(
            dlsym(RTLD_DEFAULT, "__system_property_override_add"));
    g_clear = reinterpret_cast<override_clear_fn>(
            dlsym(RTLD_DEFAULT, "__system_property_override_clear"));
    if (g_add == nullptr || g_clear == nullptr) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
                            "libc property-override symbols not found; spoofProps inert");
    }
    jclass clazz = env->FindClass("android/security/pif/PlayIntegritySpoofService");
    if (clazz == nullptr) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "class not found");
        return JNI_ERR;
    }
    if (env->RegisterNatives(clazz, kMethods,
                             sizeof(kMethods) / sizeof(kMethods[0])) != JNI_OK) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "RegisterNatives failed");
        return JNI_ERR;
    }
    return JNI_VERSION_1_6;
}
