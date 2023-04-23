#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>

#define KEY_SIZE 16
#define BLOCK_SIZE 16

int main(int argc, char *argv[]) {
    AES_KEY aes_key;
    unsigned char key[KEY_SIZE];
    unsigned char iv[BLOCK_SIZE];
    int i;

    // Check if filename and key arguments are provided
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <filename> <key>\n", argv[0]);
        return 1;
    }

    // Convert key argument to binary format
    if (strlen(argv[2]) != 2 * KEY_SIZE) {
        fprintf(stderr, "Error: Key must be %d bytes long in hex format\n", KEY_SIZE);
        return 1;
    }

    for (i = 0; i < KEY_SIZE; i++) {
        if (sscanf(argv[2] + 2 * i, "%2hhx", &key[i]) != 1) {
            fprintf(stderr, "Error: Failed to parse key\n");
            return 1;
        }
    }

    // Set AES key
    if (AES_set_decrypt_key(key, 128, &aes_key) < 0) {
        fprintf(stderr, "Error: Failed to set AES key\n");
        return 1;
    }

    memset(iv, 0x00, sizeof(iv));

    // Open input file for reading encrypted data
    FILE *fp_in = fopen(argv[1], "rb");
    if (!fp_in) {
        fprintf(stderr, "Error: Failed to open file %s\n", argv[1]);
        return 1;
    }

    // Open output file for writing decrypted data
    FILE *fp_out = fopen("decrypted_image.png", "wb");
    if (!fp_out) {
        fprintf(stderr, "Error: Failed to open output file\n");
        fclose(fp_in);
        return 1;
    }

    // Read and decrypt data in BLOCK_SIZE chunks
    unsigned char input_data[BLOCK_SIZE];
    unsigned char output_data[BLOCK_SIZE];
    int bytes_read;
    while ((bytes_read = fread(input_data, 1, BLOCK_SIZE, fp_in)) > 0) {
        // Decrypt data
        AES_cbc_encrypt(input_data, output_data, BLOCK_SIZE, &aes_key, iv, AES_DECRYPT);

        // Write decrypted data to output file
        fwrite(output_data, 1, BLOCK_SIZE, fp_out);
    }

    fclose(fp_in);
    fclose(fp_out);

    return 0;
}

