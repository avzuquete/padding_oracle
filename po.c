#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <openssl/evp.h>

char * target_message = "This is my target message, this is what I need to get!";

int oracle_aes_128_cbc(
    const unsigned char *ciphertext, int ciphertext_len,
    const unsigned char *key )
{
    assert (ciphertext_len % 16 == 0);
    assert (ciphertext_len >= 32);

    EVP_CIPHER_CTX *ctx = NULL;
    int plaintext_len = 0;
    int last_plaintext_len = 0;

    const unsigned char *iv = ciphertext;                 // First 16 bytes
    ciphertext += 16;
    ciphertext_len -= 16;

    unsigned char *plaintext = malloc( ciphertext_len );

    ctx = EVP_CIPHER_CTX_new();

    // Initialize decryption
    EVP_DecryptInit_ex( ctx, EVP_aes_128_cbc(), NULL, key, iv );

    // Decrypt update
    EVP_DecryptUpdate( ctx, plaintext, &plaintext_len, ciphertext, ciphertext_len);

    // Finalize (handles PKCS#7 padding)
    if (EVP_DecryptFinal_ex( ctx, plaintext + plaintext_len, &last_plaintext_len ) != 1) {
        // Padding error or wrong key
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        return -1;
    }
    plaintext_len += last_plaintext_len;
    plaintext[plaintext_len] = 0;

    // printf( "(%d %d)", plaintext_len, strlen( target_message ) );

    EVP_CIPHER_CTX_free(ctx);

    if (plaintext_len != strlen( target_message )) return 0; // Failure

    if (strcmp( plaintext, target_message ) != 0) {
        return 0; // Failure
    }

    printf( "Recovered the following message: %s\n", plaintext );
    
    return 1; // Success
}

int main()
{
    unsigned char key[16];
    unsigned int padding_len = 16 - (strlen( target_message ) % 16);
    int ciphertext_len = 16 + strlen(target_message) + padding_len;
    unsigned char * ciphertext = malloc( ciphertext_len );
    unsigned char * padded_plaintext = malloc( ciphertext_len );
    int fd = open( "/dev/urandom", 0 );

    read( fd, key, sizeof(key) );
    read( fd, ciphertext, ciphertext_len );
    close( fd );

    strcpy( padded_plaintext + 16, target_message );
    for (int i = 1; i <= padding_len; i++) {
        padded_plaintext[ciphertext_len - i] = (unsigned char) padding_len;
    }
    
    for (int offset = ciphertext_len - 32; offset >= 0; offset -= 16) {
        for (int byte = 15; byte >= 0; byte--) {
            for (int byte_found = 0; !byte_found;) {
                switch (oracle_aes_128_cbc( ciphertext + offset, 32, key )) {
                case -1: // padding error
                    ciphertext[offset + byte]++;
                    // putchar( '.' );
                    // fflush( stdout );
                    break;
                case 0: // wrong message
                    if (byte == 15) {
                        ciphertext[offset + byte - 1]++;
                        if (oracle_aes_128_cbc( ciphertext + offset, 32, key ) != 0) { // The byte at index 14 is relevant, did not find the correct value
                            // putchar( 'w' );
                            // fflush( stdout );
                            ciphertext[offset + byte - 1]--;
                            ciphertext[offset + byte]++; // Same as padding error
                            break;
                        }
                        // putchar( 'c' );
                        // fflush( stdout );
                        ciphertext[offset + byte - 1]--;
                    }

                    if (byte == 0) { // reached block size with correct padding
                        for (int i = 0; i < 16; i++) {
                            unsigned char diff = '\x10' ^ padded_plaintext[offset + 16 + i];
                            ciphertext[offset + i] ^= diff;
                        }
                    }
                    else {
                        for (int i = byte; i < 16; i++) {
                            ciphertext[offset + i] ^= 16 - byte;
                            ciphertext[offset + i] ^= 16 - byte + 1;
                        }
                    }
                    byte_found = 1;
                    break;
                case 1: // right message
                    printf( "Success!\n" );
                    return 0;

                }
            }
            // putchar( '+' );
            // fflush( stdout );
        }
        // putchar( '|' );
        // fflush( stdout );
    }

    if (oracle_aes_128_cbc( ciphertext, ciphertext_len, key ) != 1) {
        printf( "No success ...\n" );
    }
    else {
        printf( "Bingo!\n");
    }

    return 0;
}
