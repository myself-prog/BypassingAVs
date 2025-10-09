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

void DecryptRC4(RC4State* state, unsigned char* data, size_t len) {
    for (size_t k = 0; k < len; ++k) {
        state->i = (state->i + 1) & 0xFF;
        state->j = (state->j + state->S[state->i]) & 0xFF;
        unsigned char temp = state->S[state->i];
        state->S[state->i] = state->S[state->j];
        state->S[j] = temp;
        data[k] ^= state->S[(state->S[state->i] + state->S[state->j]) & 0xFF];
    }
}

void DecryptXOR(unsigned char* data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; ++i) data[i] ^= key;
}

unsigned char* MacToData(const char** mac_array, size_t* data_len) {
    size_t count = 0;
    while (mac_array[count]) ++count;
    *data_len = count * 6;
    unsigned char* data = (unsigned char*)malloc(*data_len);
    if (!data) return nullptr;

    for (size_t i = 0; i < count; ++i) {
        sscanf(mac_array[i], "%02hhx-%02hhx-%02hhx-%02hhx-%02hhx-%02hhx",
            &data[i * 6], &data[i * 6 + 1], &data[i * 6 + 2],
            &data[i * 6 + 3], &data[i * 6 + 4], &data[i * 6 + 5]);
    }
    return data;
}

unsigned char* DecodeBase64(const char* encoded, size_t* decoded_len) {
    const char b64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t len = strlen(encoded);
    *decoded_len = (len / 4) * 3;
    if (encoded[len - 1] == '=') (*decoded_len)--;
    if (encoded[len - 2] == '=') (*decoded_len)--;

    unsigned char* decoded = (unsigned char*)malloc(*decoded_len);
    if (!decoded) return nullptr;

    for (size_t i = 0, j = 0; i < len; ) {
        int a = strchr(b64_chars, encoded[i++]) - b64_chars;
        int b = strchr(b64_chars, encoded[i++]) - b64_chars;
        int c = (encoded[i] == '=') ? 0 : strchr(b64_chars, encoded[i++]) - b64_chars;
        int d = (encoded[i] == '=') ? 0 : strchr(b64_chars, encoded[i++]) - b64_chars;
        decoded[j++] = (a << 2) | (b >> 4);
        if (j < *decoded_len) decoded[j++] = ((b & 0xF) << 4) | (c >> 2);
        if (j < *decoded_len) decoded[j++] = ((c & 0x3) << 6) | d;
    }
    return decoded;
}