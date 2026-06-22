#ifndef __PROGTEST__
#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <climits>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <unistd.h>
#include <string>
#include <memory>
#include <vector>
#include <fstream>
#include <cassert>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

struct crypto_config
{
	const char * m_crypto_function;
	std::unique_ptr<uint8_t[]> m_key;
	std::unique_ptr<uint8_t[]> m_IV;
	size_t m_key_len;
	size_t m_IV_len;
};

#endif /* _PROGTEST_ */



// Marek Bulant - bulanma3

#define return_false { \
    out_file.close();  \
    in_file.close();   \
    EVP_CIPHER_CTX_free(ctx); \
    return false; \
}

void generate_key(unique_ptr<uint8_t[]> & key, size_t keyLen)
{
    key = make_unique<uint8_t[]>(keyLen);
    RAND_bytes(key.get(), keyLen);
}

bool encrypt_data ( const string & in_filename, const string & out_filename, crypto_config & config )
{

    ifstream in_file(in_filename, ios::binary);
    if(!in_file.is_open()) {
        return false;
    }

    ofstream out_file(out_filename, ios::binary);
    if(!out_file.is_open())
    {
        in_file.close();
        return false;
    }

    OpenSSL_add_all_algorithms();

    int otLength = 16;
    char otBuffer[16];
    int stLength = 16;
    char stBuffer[16 * 2];
    // string result;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr)
    {
        in_file.close();
        out_file.close();
        return false;
    }

    const EVP_CIPHER* cipher = EVP_get_cipherbyname(config.m_crypto_function);
    if (cipher == nullptr)
        return_false;


    // todo: check key length
    uint keyLen = EVP_CIPHER_key_length(cipher);
    uint vecLen = EVP_CIPHER_iv_length(cipher);

    // todo: can check only if it is smaller
    if(config.m_key_len != keyLen)
    {
        generate_key(config.m_key, keyLen);
        config.m_key_len = keyLen;
    }

    if(config.m_key == nullptr)
    {
        generate_key(config.m_key, keyLen);
        config.m_key_len = keyLen;
    }

    if(config.m_IV_len != vecLen)
    {
        generate_key(config.m_IV, vecLen);
        config.m_IV_len = vecLen;
    }

    if(config.m_IV == nullptr && vecLen != 0)
    {
        generate_key(config.m_IV, vecLen);
        config.m_IV_len = vecLen;
    }


    if (EVP_CipherInit_ex(ctx, cipher, nullptr, config.m_key.get(), config.m_IV.get(), 1) != 1)
        return_false;

    char tmp [18];

    // read header
    in_file.read(reinterpret_cast<char *>(tmp), 18);
    if(!in_file)
        return_false;

    // header is 18
    out_file.write(tmp, 18);
    if(!out_file)
        return_false;

    while(!in_file.eof())
    {
        in_file.read(reinterpret_cast<char *>(otBuffer), otLength);
        if(!in_file && !in_file.eof())
            return_false;

        auto temp = in_file.gcount();
        if (EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char *>(stBuffer), &stLength, reinterpret_cast<unsigned char *>(otBuffer), temp) != 1)
            return_false;

        out_file.write(stBuffer, stLength);
        if(!out_file)
            return_false;
    }

    if(EVP_EncryptFinal(ctx, reinterpret_cast<unsigned char *>(stBuffer), &stLength)!= 1)
        return_false;

    out_file.write(stBuffer, stLength);
    if(!out_file)
        return_false;

    EVP_CIPHER_CTX_free(ctx);
    in_file.close();
    out_file.close();
    return true;
}

bool decrypt_data ( const string & in_filename, const string & out_filename, crypto_config & config )
{
    ifstream in_file(in_filename, ios::binary);
    if (!in_file.is_open())
        return false;
    
    ofstream out_file(out_filename, ios::binary);
    if (!out_file.is_open()) {
        in_file.close();
        return false;
    }
    
    OpenSSL_add_all_algorithms();

    int otLength = 16;
    char otBuffer[16];
    int stLength = 16;
    char stBuffer[16 * 2];
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        in_file.close();
        out_file.close();
        return false;
    }
    
    const EVP_CIPHER* cipher = EVP_get_cipherbyname(config.m_crypto_function);
    if (cipher == nullptr)
        return_false;


    uint keyLen = EVP_CIPHER_key_length(cipher);
    uint vecLen = EVP_CIPHER_iv_length(cipher);

    if(config.m_key_len != keyLen)
        return_false;

    if(config.m_key == nullptr)
        return_false;

    if(config.m_IV_len != vecLen)
        return_false;

    if(config.m_IV == nullptr && vecLen != 0)
        return_false;

    if (EVP_CipherInit_ex(ctx, cipher, nullptr, config.m_key.get(), config.m_IV.get(), 0) != 1)
        return_false;
    
    char tmp[18];
    
    // Read header
    in_file.read(reinterpret_cast<char*>(tmp), 18);
    if (!in_file)
        return_false;
    
    // Header is 18 bytes
    out_file.write(tmp, 18);
    if (!out_file)
        return_false;
    
    while (!in_file.eof())
    {
        in_file.read(reinterpret_cast<char*>(otBuffer), otLength);
        if (!in_file && !in_file.eof())
            return_false;

        auto temp = in_file.gcount();
        if (EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(stBuffer), &stLength, reinterpret_cast<unsigned char*>(otBuffer), temp) != 1)
            return_false;

        out_file.write(stBuffer, stLength);
        if (!out_file)
        return_false;
    }
    
    if (EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(stBuffer), &stLength) != 1)
        return_false;
    
    out_file.write(stBuffer, stLength);
    if (!out_file)
        return_false;
    
    EVP_CIPHER_CTX_free(ctx);
    in_file.close();
    out_file.close();
    return true;
}


#ifndef __PROGTEST__

bool compare_files(const char* name1, const char* name2) {
    ifstream file1(name1, ios::binary);
    ifstream file2(name2, ios::binary);

    if (!file1.is_open())
        return false;

    if (!file2.is_open())
        return false;

    // Compare file sizes
    file1.seekg(0, ios::end);
    file2.seekg(0, ios::end);
    streampos size1 = file1.tellg();
    streampos size2 = file2.tellg();

    if (size1 != size2)
        return false;

    file1.seekg(0);
    file2.seekg(0);

    vector<char> buffer1((istreambuf_iterator<char>(file1)), (istreambuf_iterator<char>()));
    vector<char> buffer2((istreambuf_iterator<char>(file2)), (istreambuf_iterator<char>()));

    return buffer1 == buffer2;
}

int main ( void )
{
	crypto_config config {nullptr, nullptr, nullptr, 0, 0};

	// ECB mode
	config.m_crypto_function = "AES-128-ECB";
	config.m_key = std::make_unique<uint8_t[]>(16);
 	memset(config.m_key.get(), 0, 16);
	config.m_key_len = 16;

	assert( encrypt_data  ("homer-simpson.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson_enc_ecb.TGA") );

	assert( decrypt_data  ("homer-simpson_enc_ecb.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson.TGA") );

	assert( encrypt_data  ("UCM8.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8_enc_ecb.TGA") );

	assert( decrypt_data  ("UCM8_enc_ecb.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8.TGA") );

	assert( encrypt_data  ("image_1.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_1_enc_ecb.TGA") );

	assert( encrypt_data  ("image_2.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_2_enc_ecb.TGA") );

	assert( decrypt_data ("image_3_enc_ecb.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_3_dec_ecb.TGA") );

	assert( decrypt_data ("image_4_enc_ecb.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_4_dec_ecb.TGA") );

	// CBC mode
	config.m_crypto_function = "AES-128-CBC";
	config.m_IV = std::make_unique<uint8_t[]>(16);
	config.m_IV_len = 16;
	memset(config.m_IV.get(), 0, 16);


	assert( encrypt_data  ("UCM8.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8_enc_cbc.TGA") );

	assert( decrypt_data  ("UCM8_enc_cbc.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8.TGA") );

	assert( encrypt_data  ("homer-simpson.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson_enc_cbc.TGA") );

	assert( decrypt_data  ("homer-simpson_enc_cbc.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson.TGA") );

	assert( encrypt_data  ("image_1.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_5_enc_cbc.TGA") );

	assert( encrypt_data  ("image_2.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_6_enc_cbc.TGA") );

	assert( decrypt_data ("image_7_enc_cbc.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_7_dec_cbc.TGA") );

	assert( decrypt_data ("image_8_enc_cbc.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_8_dec_cbc.TGA") );
	return 0;
}

#endif /* _PROGTEST_ */
