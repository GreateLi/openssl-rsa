//
// Created by Administrator on 2018/10/18.
//

#ifndef TAUTHORIZATION_UTILS_IDCARDVERIFY_H
#define TAUTHORIZATION_UTILS_IDCARDVERIFY_H


#if defined(WIN32) || defined(_WIN32) || defined(WINDOWS) 
#include <cstdlib>
#include <cstring>
#include <stdio.h>
#include <stdlib.h>

#include <fstream>
#include <iostream>
#include <string>
#include <windows.h>
#include <io.h>

#include <SDKDDKVer.h>

#define WIN32_LEAN_AND_MEAN             
#define LOGD printf
#define LOGE printf
#define F_OK 0

#elif defined(LINUX)
#define LOGD printf
#define LOGE printf
#include <unistd.h>
#include <openssl/ossl_typ.h>
#include <openssl/evp.h>
#include <string.h>
#else
#include <unistd.h>

#include <curl/curl.h>
#include <openssl/ossl_typ.h>
#include <openssl/evp.h>
#include <log_helper.hpp>
#endif
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include<sstream>
using namespace std;
class utils_openssl {
public:
    static string  formatPublicKey(string Key);
    static RSA* createRSA(unsigned char* key, int flag);
    static char* genRandomString(int length);
	//私钥签名，公钥验签
	static int private_sign(const unsigned char *in_str, unsigned int in_str_len, unsigned char *outret, unsigned int *outlen, unsigned char*key);
	static int public_verify(const unsigned char *in_str, unsigned int in_len, unsigned char *outret, unsigned int outlen, unsigned char*key);

	//公钥加密，私钥解密
	static int public_encrypt(unsigned char*data, int data_len, unsigned char*key, unsigned char*encrypted);
	static int private_decrypt(unsigned char*enc_data, int data_len, unsigned char*key, unsigned char*decrypted);

	//私钥加密，公钥解密
	static unsigned char* private_encrypt(string privateKay, string strData, int * outlen);
    static string public_decrypt(unsigned char* enc_data, int data_len, unsigned char* key );
    static int is_file_exits(const char * file_path);
    static unsigned char * readFile(string file, int *len);
    static bool  writeFile(const char * path ,const char * data);

    static void  Bytes2HexStr(unsigned char *src, int srcLen, unsigned char *des);
    static unsigned char *  hexStr2Bytes(string src);
    static string Base64Encode(const char * input, int length, bool with_new_line);
    static string Base64Decode(const char * input, int length, bool with_new_line);
    static int aes_encrypt(const unsigned char* in, const unsigned char* key, const unsigned char* out, int inLen);
    static int aes_decrypt(const unsigned char* in, const unsigned char* key, unsigned char* out, int inLen);
	//生成 rsa 私钥 公钥
	static bool generateRSAKey(std::string strKey[2]);
};


#endif //TAUTHORIZATION_UTILS_IDCARDVERIFY_H
