// OpensslRSA.cpp : 定义控制台应用程序的入口点。
//

 
#include <stdio.h>
#include <tchar.h>
#include "utils_openssl.h"


char publicKey[] = "-----BEGIN PUBLIC KEY-----\n"\
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n"\
"ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+\n"\
"vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp\n"\
"fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68\n"\
"i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV\n"\
"PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy\n"\
"wQIDAQAB\n"\
"-----END PUBLIC KEY-----\n";

char privateKey[] = "-----BEGIN RSA PRIVATE KEY-----\n"\
"MIIEowIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy\n"\
"vGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+vw1HocOAZtWK0z3r26uA8kQYOKX9\n"\
"Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQApfc9jB9nTzphOgM4JiEYvlV8FLhg9\n"\
"yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68i6T4nNq7NWC+UNVjQHxNQMQMzU6l\n"\
"WCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoVPpY72+eVthKzpMeyHkBn7ciumk5q\n"\
"gLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUywQIDAQABAoIBADhg1u1Mv1hAAlX8\n"\
"omz1Gn2f4AAW2aos2cM5UDCNw1SYmj+9SRIkaxjRsE/C4o9sw1oxrg1/z6kajV0e\n"\
"N/t008FdlVKHXAIYWF93JMoVvIpMmT8jft6AN/y3NMpivgt2inmmEJZYNioFJKZG\n"\
"X+/vKYvsVISZm2fw8NfnKvAQK55yu+GRWBZGOeS9K+LbYvOwcrjKhHz66m4bedKd\n"\
"gVAix6NE5iwmjNXktSQlJMCjbtdNXg/xo1/G4kG2p/MO1HLcKfe1N5FgBiXj3Qjl\n"\
"vgvjJZkh1as2KTgaPOBqZaP03738VnYg23ISyvfT/teArVGtxrmFP7939EvJFKpF\n"\
"1wTxuDkCgYEA7t0DR37zt+dEJy+5vm7zSmN97VenwQJFWMiulkHGa0yU3lLasxxu\n"\
"m0oUtndIjenIvSx6t3Y+agK2F3EPbb0AZ5wZ1p1IXs4vktgeQwSSBdqcM8LZFDvZ\n"\
"uPboQnJoRdIkd62XnP5ekIEIBAfOp8v2wFpSfE7nNH2u4CpAXNSF9HsCgYEA2l8D\n"\
"JrDE5m9Kkn+J4l+AdGfeBL1igPF3DnuPoV67BpgiaAgI4h25UJzXiDKKoa706S0D\n"\
"4XB74zOLX11MaGPMIdhlG+SgeQfNoC5lE4ZWXNyESJH1SVgRGT9nBC2vtL6bxCVV\n"\
"WBkTeC5D6c/QXcai6yw6OYyNNdp0uznKURe1xvMCgYBVYYcEjWqMuAvyferFGV+5\n"\
"nWqr5gM+yJMFM2bEqupD/HHSLoeiMm2O8KIKvwSeRYzNohKTdZ7FwgZYxr8fGMoG\n"\
"PxQ1VK9DxCvZL4tRpVaU5Rmknud9hg9DQG6xIbgIDR+f79sb8QjYWmcFGc1SyWOA\n"\
"SkjlykZ2yt4xnqi3BfiD9QKBgGqLgRYXmXp1QoVIBRaWUi55nzHg1XbkWZqPXvz1\n"\
"I3uMLv1jLjJlHk3euKqTPmC05HoApKwSHeA0/gOBmg404xyAYJTDcCidTg6hlF96\n"\
"ZBja3xApZuxqM62F6dV4FQqzFX0WWhWp5n301N33r0qR6FumMKJzmVJ1TA8tmzEF\n"\
"yINRAoGBAJqioYs8rK6eXzA8ywYLjqTLu/yQSLBn/4ta36K8DyCoLNlNxSuox+A5\n"\
"w6z2vEfRVQDq4Hm4vBzjdi3QfYLNkTiTqLcvgWZ+eX44ogXtdTDO7c+GeMKWz4XX\n"\
"uJSUVL5+CVjKLjZEJ6Qc2WZLl94xSwL71E41H4YciVnSCQxVc4Jw\n"\
"-----END RSA PRIVATE KEY-----\n";


//把字符串写成public.pem文件
int createPublicFile(char *file, const string &pubstr)
{
	if (pubstr.empty())
	{
		printf("public key read error\n");
		return (-1);
	}
	int len = pubstr.length();
	string tmp = pubstr;
	for (int i = 64; i<len; i += 64)
	{
		if (tmp[i] != '\n')
		{
			tmp.insert(i, "\n");
		}
		i++;
	}
	tmp.insert(0, "-----BEGIN PUBLIC KEY-----\n");
	tmp.append("\n-----END PUBLIC KEY-----\n");

	//写文件
	ofstream fout(file);
	fout << tmp;

	return (0);
}

//把字符串写成private.pem文件
int createPrivateFile(char *file, const string &pristr)
{
	if (pristr.empty())
	{
		printf("public key read error\n");
		return (-1);
	}
	int len = pristr.length();
	string tmp = pristr;
	for (int i = 64; i<len; i += 64)
	{
		if (tmp[i] != '\n')
		{
			tmp.insert(i, "\n");
		}
		i++;
	}
	tmp.insert(0, "-----BEGIN RSA PRIVATE KEY-----\n");
	tmp.append("-----END RSA PRIVATE KEY-----\n");

	//写文件
	ofstream fout(file);
	fout << tmp;

	return (0);
}

 
 
int main()
{
	char plainText[2048 / 8] = "ddfdf@$%j jkfhhhhhhhgffdddd";//key length : 2048  
	printf("create pem file\n");
	string strPublicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQChNr0TmflORv9C62+tSAYhyj4DwB6fyOHqttddq8Y+R+8cIGT7EKuqSRuUUuLVBN6IIjd14UkxxtjHqrDxPWZz9WfX0LB2lTmnSdkg9Q10IfP9ZrVCW8Pe5vJ7gt5iQ4lOebdqR47+ef9E7oE+eJFQhxSYGGy/FnKjBkadJQtwPQIDAQAB";
	int file_ret = createPublicFile("public_test.pem", strPublicKey);

	unsigned char encrypted[4098] = {};
	unsigned char decrypted[4098] = {};
	unsigned char signret[4098] = {};
	unsigned int siglen;

	//明文  
	 
	const string srcStr = "skl;dfhas;lkdfhslk;dfhsidfhoiehrfoishfsidf";
	cout << "srcStr: " << srcStr << endl;
	int outlen = -1;

	unsigned char* desStr = utils_openssl::private_encrypt(privateKey, srcStr, &outlen);
	//cout << "desStr: " << desStr << endl;

	string srcbStr = utils_openssl::public_decrypt(desStr, outlen, (unsigned char*)publicKey);

	if (0 == srcStr.compare(srcbStr))
	{
		printf ( "successful\n");
	}
	else
	{
		printf("failed\n" );
	}

	//以下未经优化，如使用可自己优化
	printf("source data=[%s]\n", plainText);

	printf("public encrytpt ----private decrypt \n\n");
	int encrypted_length = utils_openssl::public_encrypt((unsigned char*)plainText, strlen(plainText), (unsigned char*)publicKey, encrypted);
	if (encrypted_length == -1)
	{
		printf("encrypted error \n");
		exit(0);
	}
	printf("Encrypted length =%d\n", encrypted_length);
	int decrypted_length = utils_openssl::private_decrypt((unsigned char*)encrypted, encrypted_length, (unsigned char*)privateKey, decrypted);
	if (decrypted_length == -1)
	{
		printf("decrypted error \n");
		exit(0);
	}
	printf("DecryptedText =%s\n", decrypted);
	printf("DecryptedLength =%d\n", decrypted_length);

	printf("private encrytpt ----public decrypt \n\n");
 
	printf("DecryptedText =%s\n", decrypted);
	printf("DecryptedLength =%d\n", decrypted_length);

	printf("\nprivate sign ----public verify \n\n");
	int ret = utils_openssl::private_sign((const unsigned char*)plainText, strlen(plainText), signret, &siglen, (unsigned char*)privateKey);
	printf("sign ret =[%d]\n", ret);
	ret = utils_openssl::public_verify((const unsigned char*)plainText, strlen(plainText), signret, siglen, (unsigned char*)publicKey);
	printf("verify ret =[%d]\n", ret);
 


    return 0;
}

