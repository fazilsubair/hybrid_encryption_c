#include <stdio.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

int main() {
    EC_KEY *ec_key = NULL;
    const EC_GROUP *group = NULL;
    const BIGNUM *priv_key = NULL;
    const EC_POINT *pub_key = NULL;

    // Initialize OpenSSL's random number generator
    RAND_poll();
    if (RAND_status() == 0) {
        printf("OpenSSL random number generator not seeded\n");
        exit(1);
    }

    // Prompt the user to enter a password
    char password[80];
    printf("Enter a password: ");
    scanf("%s", password);

    // Derive a private key from the password using a key derivation function
    unsigned char salt[8];
    RAND_bytes(salt, sizeof(salt));
    unsigned char derived_key[32];
    int iterations = 10000;
    if (PKCS5_PBKDF2_HMAC_SHA1(password, strlen(password), salt, sizeof(salt), iterations, sizeof(derived_key), derived_key) != 1) {
        printf("Error: Could not derive private key\n");
        exit(1);
    }

    // Convert the derived key to a BIGNUM
    priv_key = BN_bin2bn(derived_key, sizeof(derived_key), NULL);

    // Choose an elliptic curve
    ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (ec_key == NULL) {
        printf("Error: Could not create EC key\n");
        exit(1);
    }

    // Set the private key
    if (EC_KEY_set_private_key(ec_key, priv_key) != 1) {
        printf("Error: Could not set private key\n");
        exit(1);
    }

    // Compute the public key
    if (EC_KEY_generate_key(ec_key) != 1) {
        printf("Error: Could not generate EC key pair\n");
        exit(1);
    }

    // Extract the public key
    pub_key = EC_KEY_get0_public_key(ec_key);
    group = EC_KEY_get0_group(ec_key);

    // Print the private and public keys in hex format
    char *priv_key_hex = BN_bn2hex(priv_key);
    char *pub_key_hex = EC_POINT_point2hex(group, pub_key, POINT_CONVERSION_UNCOMPRESSED, NULL);
    printf("Private key: %s\n", priv_key_hex);
    printf("Public key: %s\n", pub_key_hex);

    // Free memory
    OPENSSL_free(priv_key_hex);
    OPENSSL_free(pub_key_hex);
    EC_KEY_free(ec_key);

    return 0;
}

