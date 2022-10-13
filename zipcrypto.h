#include <zlib.h>
#include <inttypes.h>
#include <time.h>

#define RAND_HEAD_LEN 12

static uint8_t decrypt_byte(uint32_t *pkeys)
{
    unsigned temp;

    temp = (*(pkeys + 2)) | 2;

    return (uint8_t)(((temp * (temp ^ 1)) >> 8) & 0xff);
}

static uint32_t crc32_update(uint32_t value, uint8_t *buf, int size)
{
    return (uint32_t)crc32((z_crc_t)value, buf, size);
}

static uint8_t update_keys(uint32_t *pkeys, uint8_t c)
{
    uint8_t buf = c;

    *(pkeys + 0) = (uint32_t)~crc32_update(~(*(pkeys + 0)), &buf, 1);

    *(pkeys + 1) += *(pkeys + 0) & 0xff;
    *(pkeys + 1) *= 134775813L;
    *(pkeys + 1) += 1;

    buf = (uint8_t)(*(pkeys + 1) >> 24);
    (*(pkeys + 2)) = (uint32_t)~crc32_update(~(*(pkeys + 2)), &buf, 1);

    return (uint8_t)c;
}

static void init_keys(uint32_t *pkeys, char *password)
{
    *(pkeys + 0) = 305419896L;
    *(pkeys + 1) = 591751049L;
    *(pkeys + 2) = 878082192L;

    while (*password != NULL) {
        update_keys(pkeys, (uint8_t)*password);
        password += 1;
    }
}

#define crypt_encode(pkeys, c, t) \
    (t = decrypt_byte(pkeys), update_keys(pkeys, (uint8_t)c), (uint8_t)(t ^ (c)))

size_t encrypt_init(uint8_t *header, uint32_t *pkeys, char *password,
        uint16_t verifier)
{
    int i, c, t;

    if (password == NULL)
        return 0;

    init_keys(pkeys, password);
    
    /* First generate RAND_HEAD_LEN - 2 random bytes. Encrypt output of rand(),
     * since rand() is poorly implemented
     */
    for (i = 0; i < RAND_HEAD_LEN - 2; i++) {
        c = (rand() >> 7) & 0xff;
        header[i] = (uint8_t)crypt_encode(pkeys, c, t);
    }

    /* Encrypt random header (last two bytes is high word of crc or dos_time,
     * depend on the flag bit 3)
     */
    init_keys(pkeys, password);
    for (i = 0; i < RAND_HEAD_LEN - 2; i++)
        header[i] = crypt_encode(pkeys, header[i], t);

    uint8_t verify1 = (uint8_t)((verifier >> 8) & 0xff);
    uint8_t verify2 = (uint8_t)(verifier & 0xff);

    header[i++] = crypt_encode(pkeys, verify1, t);
    header[i++] = crypt_encode(pkeys, verify2, t);

    return i;
}
