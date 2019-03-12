#include<stdio.h>
#include "mbedtls/aes.h"
#include "mbedtls/compat-1.3.h"
#define AES_ECB 0
#define AES_CBC 1
#define AES_CFB 2
#define AES_OFB 3

#define MODE AES_CFB

unsigned char key[16] = { 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 };
unsigned char plain[32] = { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };
unsigned char plain_decrypt[32] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char IV[16];
unsigned char cypher[32];
int i = 0;
mbedtls_aes_context aes;

void SetIV()
{
	int i;
	for (i = 0; i < 16; i++)
	{
		IV[i] = 0x55;
	}
}

int main()
{
    size_t iv_offset = 0;
    int i = 0;
    uint8_t key_str[20] = {0x64, 0xcf, 0x9c, 0x7a, 0xbc, 0x50, 0xb8, 0x88, 0xaf, 0x65, 0xf4, 0x9d, 0x52, 0x19, 0x44, 0xb2};
    uint8_t iv_str[20] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t src_str[20] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t dst_str[20] = {0xf7, 0xef, 0xc8, 0x9d, 0x5d, 0xba, 0x57, 0x81, 0x04, 0x01, 0x6c, 0xe5, 0xad, 0x65, 0x9c, 0x05};
    uint8_t output[20];
    uint8_t key_str1[20] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t iv_str1[20] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; 
    uint8_t src_str1[20] = {0x10, 0xd3, 0xed, 0x7a, 0x6f, 0xe1, 0x5a, 0xb4, 0xd9, 0x1a, 0xcb, 0xc7, 0xd0, 0x76, 0x7a, 0xb1};
    //memset(key_str, 0x00, 100);
    //memset(iv_str, 0x00, 100);
    //memset(src_str, 0x00, 100);
    //memset(dst_str, 0x00, 100);
    //memset(output, 0x00, 100);
    mbedtls_aes_init( &aes );
	if (MODE == AES_ECB)
	{
		    mbedtls_aes_setkey_enc(&aes, key, 128);//  set encrypt key			
			mbedtls_aes_crypt_ecb(&aes, AES_ENCRYPT, plain, cypher);
			mbedtls_aes_setkey_dec(&aes, key, 128);//  set decrypt key
			mbedtls_aes_crypt_ecb(&aes, AES_DECRYPT, cypher, plain_decrypt);
			i++;			
	}
	if (MODE == AES_CBC)
	{
		    mbedtls_aes_setkey_enc(&aes, key, 128);//  set encrypt key
			SetIV();
			mbedtls_aes_crypt_cbc(&aes, AES_ENCRYPT, 32, IV, plain, cypher);
			mbedtls_aes_setkey_dec(&aes, key, 128);//  set decrypt key
			SetIV();
			mbedtls_aes_crypt_cbc(&aes, AES_DECRYPT, 32, IV, cypher, plain_decrypt);
			i++;			
	}
    if (MODE == AES_CFB)
	{
		    mbedtls_aes_setkey_enc(&aes, key_str, 128);//  set encrypt key
			SetIV();
            mbedtls_aes_crypt_cfb128( &aes, MBEDTLS_AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output );
			//mbedtls_aes_crypt_cbc(&aes, AES_ENCRYPT, 32, IV, plain, cypher);
            for(i=0; i<16; i++)
            {
                printf("iv[%d] : %x \n", i, iv_str[i]);
            }
			mbedtls_aes_setkey_enc(&aes, key_str, 128);//  set decrypt key
			//SetIV();
            for (i = 0; i < 16; i++)
            {
                iv_str[i] = 0x00;
            }
            iv_offset = 0;
            mbedtls_aes_crypt_cfb128( &aes, MBEDTLS_AES_DECRYPT, 16, &iv_offset, iv_str, dst_str, plain_decrypt );
			//mbedtls_aes_crypt_cbc(&aes, AES_DECRYPT, 32, IV, cypher, plain_decrypt);
			i++;			
	}
    if (MODE == AES_OFB)
	{
		    mbedtls_aes_setkey_enc(&aes, key, 128);//  set encrypt key
			SetIV();
            
			mbedtls_aes_crypt_cbc(&aes, AES_ENCRYPT, 32, IV, plain, cypher);
			mbedtls_aes_setkey_dec(&aes, key, 128);//  set decrypt key
			SetIV();
			mbedtls_aes_crypt_cbc(&aes, AES_DECRYPT, 32, IV, cypher, plain_decrypt);
			i++;			
	}

    for(i=0; i<32; i++)
    {
        printf("dst_str[%d]:%x plain_decrypt[%d]:%x \n", i, dst_str[i], i, plain_decrypt[i]);
    }
}
