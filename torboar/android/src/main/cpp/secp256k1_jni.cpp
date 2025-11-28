/*
 * ============================================================
 *  JNI Bridge — libsecp256k1 Integration Layer
 * ============================================================
 *
 * This file implements the native bridge between TorboarPlugin.java
 * and the C library libsecp256k1. Each JNI function here wraps a 
 * specific libsecp256k1 API call.
 *
 * Because each libsecp256k1 function has its own C signature and data
 * direction (in, out, or in-place), the JNI wrappers vary slightly in how
 * they handle Java arrays and return results. 
 *
 * Results are returned as HashMap<String,Object> objects containing both
 * the status code ("res") and any output byte arrays. 
 */
 
 

#include <jni.h>
#include <string>
#include <secp256k1.h> 
#include "secp256k1_schnorr.h"   
#include <android/log.h>
#include <cstring>  // for memset, sprintf
#include <string.h> // specifically for memcpy

// ============================================================
// Global Context
// ============================================================ 
  // RFC6979 adapter for hardened schnorr custom sign
 
static int rfc6979_nonce_adapter(
    unsigned char *nonce32,
    const unsigned char *msg,
    size_t msglen,
    const unsigned char *key32,
    const unsigned char *xonly_pk32,
    const unsigned char *algo,
    size_t algolen,
    void *data
) {
    (void)msglen;
    (void)xonly_pk32;
    return secp256k1_nonce_function_rfc6979(
        nonce32,
        msg,
        key32,
        algo,
        data,
        0
    );
}

 
secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

extern "C"
JNIEXPORT jobject JNICALL
Java_com_selene_torboar_Secp256k1Bridge_secp256k1EcPubkeyTweakMul(
    JNIEnv *env,
    jclass clazz,
    jlong ctxPtr,
    jbyteArray inputPubkey,   // [IN]  64-byte pubkey struct
    jbyteArray scalar         // [IN]  32-byte tweak
) {
    secp256k1_context *ctx = reinterpret_cast<secp256k1_context *>(ctxPtr);
    jbyte *pubkeyBytes = env->GetByteArrayElements(inputPubkey, nullptr);
    jbyte *scalarBytes = env->GetByteArrayElements(scalar, nullptr);

    int result = 0;
    jbyteArray pubkeyOut = env->NewByteArray(64);

    if (ctx && pubkeyBytes && scalarBytes) {
        // Copy input pubkey into working buffer
        unsigned char pubkeyTmp[64];
        memcpy(pubkeyTmp, pubkeyBytes, 64);

        // Perform tweak multiply
        result = secp256k1_ec_pubkey_tweak_mul(
            ctx,
            reinterpret_cast<secp256k1_pubkey *>(pubkeyTmp),
            reinterpret_cast<const unsigned char *>(scalarBytes)
        );

        // If successful, copy result to output array
        if (result) {
            env->SetByteArrayRegion(pubkeyOut, 0, 64, reinterpret_cast<jbyte *>(pubkeyTmp));
        }
    }

    env->ReleaseByteArrayElements(inputPubkey, pubkeyBytes, JNI_ABORT);
    env->ReleaseByteArrayElements(scalar, scalarBytes, JNI_ABORT);

    // --- Prepare return map ---
    jclass mapClass = env->FindClass("java/util/HashMap");
    jmethodID init = env->GetMethodID(mapClass, "<init>", "()V");
    jobject mapObj = env->NewObject(mapClass, init);
    jmethodID put = env->GetMethodID(
        mapClass,
        "put",
        "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;"
    );

    // Add "res"
    jclass integerClass = env->FindClass("java/lang/Integer");
    jmethodID intCtor = env->GetMethodID(integerClass, "<init>", "(I)V");
    jobject resObj = env->NewObject(integerClass, intCtor, result);
    env->CallObjectMethod(mapObj, put, env->NewStringUTF("res"), resObj);

    // Add "pubkey"
    env->CallObjectMethod(mapObj, put, env->NewStringUTF("pubkey"), pubkeyOut);

    return mapObj;
}

  
  extern "C"
JNIEXPORT jobject JNICALL
Java_com_selene_torboar_Secp256k1Bridge_secp256k1EcPubkeySerialize(
    JNIEnv *env,
    jclass clazz,
    jlong ctxPtr,
    jbyteArray input,      // [IN] secp256k1_pubkey (64 bytes)
    jint flags,            // [IN] 258 = compressed, 2 = uncompressed
    jbyteArray outputBuf   // [OUT] preallocated by Java
) {
    secp256k1_context *ctx = reinterpret_cast<secp256k1_context *>(ctxPtr);
    if (!ctx) return nullptr;

    jbyte *inputBytes = env->GetByteArrayElements(input, nullptr);
    jbyte *outputBytes = env->GetByteArrayElements(outputBuf, nullptr);

    size_t outputLen = env->GetArrayLength(outputBuf);
    int result = secp256k1_ec_pubkey_serialize(
        ctx,
        reinterpret_cast<unsigned char *>(outputBytes),
        &outputLen,
        reinterpret_cast<const secp256k1_pubkey *>(inputBytes),
        static_cast<unsigned int>(flags)
    );

    env->ReleaseByteArrayElements(input, inputBytes, JNI_ABORT);
    env->ReleaseByteArrayElements(outputBuf, outputBytes, 0);

    // --- Build HashMap<String,Object> { "res": int, "pubkey": byte[] } ---
    jclass mapClass = env->FindClass("java/util/HashMap");
    jmethodID mapInit = env->GetMethodID(mapClass, "<init>", "()V");
    jmethodID mapPut = env->GetMethodID(mapClass, "put",
        "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");
    jobject resultMap = env->NewObject(mapClass, mapInit);

    // Add res
    jclass integerClass = env->FindClass("java/lang/Integer");
    jmethodID integerInit = env->GetMethodID(integerClass, "<init>", "(I)V");
    jobject resObj = env->NewObject(integerClass, integerInit, result);
    jstring keyRes = env->NewStringUTF("res");
    env->CallObjectMethod(resultMap, mapPut, keyRes, resObj);

    // Add pubkey (copy of outputBuf)
    jstring keyPubkey = env->NewStringUTF("pubkey");
    env->CallObjectMethod(resultMap, mapPut, keyPubkey, outputBuf);
 

    return resultMap;
}

  
 
 extern "C"
JNIEXPORT jobject JNICALL
Java_com_selene_torboar_Secp256k1Bridge_secp256k1EcPubkeyCombine(
    JNIEnv *env,
    jclass clazz,
    jlong ctxPtr,
    jbyteArray outputBuf,   // [OUT] 64 bytes
    jbyteArray inputBuf1,   // [IN] 64 bytes
    jbyteArray inputBuf2    // [IN] 64 bytes
) {
     
    secp256k1_context *ctx = reinterpret_cast<secp256k1_context *>(ctxPtr);
    if (!ctx) return nullptr;

    jbyte *outBytes = env->GetByteArrayElements(outputBuf, nullptr);
    jbyte *inBytes1 = env->GetByteArrayElements(inputBuf1, nullptr);
    jbyte *inBytes2 = env->GetByteArrayElements(inputBuf2, nullptr);

    int result = 0;
    if (outBytes && inBytes1 && inBytes2) {
        const secp256k1_pubkey *pubkeys[2];
        pubkeys[0] = reinterpret_cast<const secp256k1_pubkey *>(inBytes1);
        pubkeys[1] = reinterpret_cast<const secp256k1_pubkey *>(inBytes2);

       

        result = secp256k1_ec_pubkey_combine(
            ctx,
            reinterpret_cast<secp256k1_pubkey *>(outBytes),
            pubkeys,
            2
        );
 
    }

    env->ReleaseByteArrayElements(outputBuf, outBytes, 0);
    env->ReleaseByteArrayElements(inputBuf1, inBytes1, JNI_ABORT);
    env->ReleaseByteArrayElements(inputBuf2, inBytes2, JNI_ABORT);

    // --- Build result map ---
    jclass mapClass = env->FindClass("java/util/HashMap");
    jmethodID mapInit = env->GetMethodID(mapClass, "<init>", "()V");
    jmethodID mapPut = env->GetMethodID(mapClass, "put",
        "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");
    jobject resultMap = env->NewObject(mapClass, mapInit);

    jclass integerClass = env->FindClass("java/lang/Integer");
    jmethodID intCtor = env->GetMethodID(integerClass, "<init>", "(I)V");
    jobject resObj = env->NewObject(integerClass, intCtor, result);

    env->CallObjectMethod(resultMap, mapPut, env->NewStringUTF("res"), resObj);
    env->CallObjectMethod(resultMap, mapPut, env->NewStringUTF("pubkey"), outputBuf);
 
    return resultMap;
}


 
extern "C"
JNIEXPORT jlong JNICALL
Java_com_selene_torboar_Secp256k1Bridge_createSecp256k1Context(JNIEnv *env, jclass clazz) {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    return reinterpret_cast<jlong>(ctx);
}
 

   
   extern "C"
JNIEXPORT jobject JNICALL
Java_com_selene_torboar_Secp256k1Bridge_secp256k1EcPubkeyParse(
    JNIEnv *env,
    jclass clazz,
    jlong ctxPtr,
    jbyteArray unusedPubkeyOut,  // not used anymore, just placeholder
    jbyteArray input,
    jint inputLen
) {
     

    secp256k1_context *ctx = reinterpret_cast<secp256k1_context *>(ctxPtr);
    if (!ctx) return nullptr;

    jbyte *inputBytes = env->GetByteArrayElements(input, nullptr);
    if (!inputBytes) return nullptr;

    // Parse into native struct
    secp256k1_pubkey pubkey;
    int result = secp256k1_ec_pubkey_parse(
        ctx,
        &pubkey,
        reinterpret_cast<const unsigned char *>(inputBytes),
        static_cast<size_t>(inputLen)
    );

    env->ReleaseByteArrayElements(input, inputBytes, JNI_ABORT);

    //  Create a *fresh* Java byte[] with the parsed data
    jsize outLen = sizeof(secp256k1_pubkey);
    jbyteArray pubkeyBytes = env->NewByteArray(outLen);
    if (result == 1 && pubkeyBytes != nullptr) {
        env->SetByteArrayRegion(pubkeyBytes, 0, outLen, reinterpret_cast<const jbyte*>(&pubkey));

        
    } else {
        __android_log_write(ANDROID_LOG_ERROR, "fusionservice TorboarNative",
                            " secp256k1_ec_pubkey_parse() failed or pubkeyBytes null");
    }

    //  Build HashMap<String,Object> { "res": int, "pubkey": byte[] }
    jclass mapClass = env->FindClass("java/util/HashMap");
    jmethodID mapInit = env->GetMethodID(mapClass, "<init>", "()V");
    jmethodID mapPut = env->GetMethodID(mapClass, "put",
        "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");
    jobject resultMap = env->NewObject(mapClass, mapInit);

    jclass integerClass = env->FindClass("java/lang/Integer");
    jmethodID integerInit = env->GetMethodID(integerClass, "<init>", "(I)V");
    jobject resObj = env->NewObject(integerClass, integerInit, result);

    jstring keyRes = env->NewStringUTF("res");
    env->CallObjectMethod(resultMap, mapPut, keyRes, resObj);

    jstring keyPubkey = env->NewStringUTF("pubkey");
    env->CallObjectMethod(resultMap, mapPut, keyPubkey, pubkeyBytes);

    return resultMap;
}

   
  
extern "C"
JNIEXPORT jobject JNICALL
Java_com_selene_torboar_Secp256k1Bridge_secp256k1EcPubkeyCreate(
    JNIEnv *env,
    jclass clazz,
    jlong ctxPtr,
    jbyteArray scalar    // [IN] 32-byte private key scalar
) {
    secp256k1_context *ctx = reinterpret_cast<secp256k1_context *>(ctxPtr);
    if (!ctx) return nullptr;

    jbyte *scalarBytes = env->GetByteArrayElements(scalar, nullptr);
    jbyteArray pubkeyOut = env->NewByteArray(64);

    int result = 0;

    if (scalarBytes) {
        unsigned char pubkeyTmp[64];
        memset(pubkeyTmp, 0, sizeof(pubkeyTmp));

        result = secp256k1_ec_pubkey_create(
            ctx,
            reinterpret_cast<secp256k1_pubkey *>(pubkeyTmp),
            reinterpret_cast<const unsigned char *>(scalarBytes)
        );

        if (result) {
            env->SetByteArrayRegion(pubkeyOut, 0, 64, reinterpret_cast<jbyte *>(pubkeyTmp));
        }
    }

    env->ReleaseByteArrayElements(scalar, scalarBytes, JNI_ABORT);

    // --- Return { res, pubkey } map ---
    jclass mapClass = env->FindClass("java/util/HashMap");
    jmethodID mapInit = env->GetMethodID(mapClass, "<init>", "()V");
    jmethodID mapPut = env->GetMethodID(mapClass, "put",
        "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");
    jobject resultMap = env->NewObject(mapClass, mapInit);

    jclass integerClass = env->FindClass("java/lang/Integer");
    jmethodID intCtor = env->GetMethodID(integerClass, "<init>", "(I)V");
    jobject resObj = env->NewObject(integerClass, intCtor, result);

    env->CallObjectMethod(resultMap, mapPut, env->NewStringUTF("res"), resObj);
    env->CallObjectMethod(resultMap, mapPut, env->NewStringUTF("pubkey"), pubkeyOut);

    return resultMap;
}


 extern "C"
JNIEXPORT jobject JNICALL
Java_com_selene_torboar_Secp256k1Bridge_secp256k1EcPubkeyNegate(
    JNIEnv *env,
    jclass clazz,
    jlong ctxPtr,
    jbyteArray input    // [IN] 64-byte pubkey struct
) {
    secp256k1_context *ctx = reinterpret_cast<secp256k1_context *>(ctxPtr);
    if (!ctx) {
        __android_log_write(ANDROID_LOG_DEBUG, "fusionservice TorboarNative",
                " JNI negate  ctxPtr is null");
        return nullptr;
    }

    jbyte *inputBytes = env->GetByteArrayElements(input, nullptr);
    if (!inputBytes) {
        __android_log_write(ANDROID_LOG_DEBUG, "fusionservice TorboarNative",
                " JNI negate  failed to get inputBytes");
        return nullptr;
    }

    

    unsigned char pubkeyTmp[64];
    memcpy(pubkeyTmp, inputBytes, 64);

    int result = secp256k1_ec_pubkey_negate(
        ctx,
        reinterpret_cast<secp256k1_pubkey *>(pubkeyTmp)
    );
 

    jbyteArray output = env->NewByteArray(64);
    if (result == 1) {
        env->SetByteArrayRegion(output, 0, 64, reinterpret_cast<jbyte *>(pubkeyTmp));
        
    } else {
        // fill with zeros to make output defined
        jbyte zeroBuf[64] = {0};
        env->SetByteArrayRegion(output, 0, 64, zeroBuf);
         
    }

    env->ReleaseByteArrayElements(input, inputBytes, JNI_ABORT);

    // --- Return { res, pubkey } map ---
    jclass mapClass = env->FindClass("java/util/HashMap");
    jmethodID mapInit = env->GetMethodID(mapClass, "<init>", "()V");
    jmethodID mapPut = env->GetMethodID(mapClass, "put",
        "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");
    jobject resultMap = env->NewObject(mapClass, mapInit);

    jclass integerClass = env->FindClass("java/lang/Integer");
    jmethodID intCtor = env->GetMethodID(integerClass, "<init>", "(I)V");
    jobject resObj = env->NewObject(integerClass, intCtor, result);

    env->CallObjectMethod(resultMap, mapPut, env->NewStringUTF("res"), resObj);
    env->CallObjectMethod(resultMap, mapPut, env->NewStringUTF("pubkey"), output);
 
    return resultMap;
}

 
  
  
extern "C"
JNIEXPORT jobject JNICALL
Java_com_selene_torboar_Secp256k1Bridge_secp256k1SchnorrSign32(
    JNIEnv *env,
    jclass clazz,
    jlong ctxPtr,
    jbyteArray msg32,
    jbyteArray seckey32,
    jbyteArray auxRand32 // ignored
) {
    secp256k1_context *ctx = reinterpret_cast<secp256k1_context *>(ctxPtr);
    if (!ctx) return nullptr;

    if (env->GetArrayLength(msg32) != 32 || env->GetArrayLength(seckey32) != 32) {
        // optional: enforce sizes
        return nullptr;
    }

    jbyte *msgBytes    = env->GetByteArrayElements(msg32, nullptr);
    jbyte *seckeyBytes = env->GetByteArrayElements(seckey32, nullptr);

    unsigned char sigOut[64];

    // EC (Amaury) Schnorr sign: ctx, sig64, msg32, seckey32, noncefn, ndata
    int resSign = secp256k1_schnorr_sign(
        ctx,
        sigOut,
        reinterpret_cast<const unsigned char *>(msgBytes),
        reinterpret_cast<const unsigned char *>(seckeyBytes),
        NULL,
        NULL
    );

    env->ReleaseByteArrayElements(msg32, msgBytes, JNI_ABORT);
    env->ReleaseByteArrayElements(seckey32, seckeyBytes, JNI_ABORT);

    // return { res, sig? }
    jclass mapClass = env->FindClass("java/util/HashMap");
    jmethodID mapInit = env->GetMethodID(mapClass, "<init>", "()V");
    jmethodID mapPut  = env->GetMethodID(mapClass, "put",
        "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");
    jobject resultMap = env->NewObject(mapClass, mapInit);

    jclass integerClass = env->FindClass("java/lang/Integer");
    jmethodID intCtor = env->GetMethodID(integerClass, "<init>", "(I)V");
    jobject resObj = env->NewObject(integerClass, intCtor, resSign);
    env->CallObjectMethod(resultMap, mapPut, env->NewStringUTF("res"), resObj);

    if (resSign) {
        jbyteArray sigArray = env->NewByteArray(64);
        env->SetByteArrayRegion(sigArray, 0, 64, reinterpret_cast<const jbyte *>(sigOut));
        env->CallObjectMethod(resultMap, mapPut, env->NewStringUTF("sig"), sigArray);
    }

    return resultMap;
}


