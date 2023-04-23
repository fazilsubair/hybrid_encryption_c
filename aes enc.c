#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define KEY_SIZE 16
#define BLOCK_SIZE 16

int main(int argc, char *argv[]) {
    AES_KEY aes_key;
    unsigned char key[KEY_SIZE];
    unsigned char iv[BLOCK_SIZE];
    int i;

    // Check if filename argument is provided
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    // Generate random key
    if (RAND_bytes(key, KEY_SIZE) != 1) {
        fprintf(stderr, "Error: Failed to generate random key\n");
        return 1;
    }

    printf("Key: ");
    for (i = 0; i < KEY_SIZE; i++) {
        printf("%02x", key[i]);
    }
    printf("\n");

    // Set AES key
    if (AES_set_encrypt_key(key, 128, &aes_key) < 0) {
        fprintf(stderr, "Error: Failed to set AES key\n");
        return 1;
    }

    memset(iv, 0x00, sizeof(iv));

    // Read in image file
    FILE *fp_in = fopen(argv[1], "rb");
    if (!fp_in) {
        fprintf(stderr, "Error: Failed to open file %s\n", argv[1]);
        return 1;
    }

    // Open output file for writing encrypted data
    FILE *fp_out = fopen("encrypted_image.dat", "wb");
    if (!fp_out) {
        fprintf(stderr, "Error: Failed to open output file\n");
        fclose(fp_in);
        return 1;
    }

    // Read and encrypt data in BLOCK_SIZE chunks
    unsigned char input_data[BLOCK_SIZE];
    unsigned char output_data[BLOCK_SIZE];
    int bytes_read;
    while ((bytes_read = fread(input_data, 1, BLOCK_SIZE, fp_in)) > 0) {
        // Pad data if necessary
        if (bytes_read < BLOCK_SIZE) {
            memset(input_data + bytes_read, BLOCK_SIZE - bytes_read, BLOCK_SIZE - bytes_read);
        }

        // Encrypt data
        AES_cbc_encrypt(input_data, output_data, BLOCK_SIZE, &aes_key, iv, AES_ENCRYPT);

        // Write encrypted data to output file
        fwrite(output_data, 1, BLOCK_SIZE, fp_out);
    }

    fclose(fp_in);
    fclose(fp_out);

    return 0;
}

