/*
 * OQS OpenSSL 3 provider
 *
 * Composite Signatures code.
 *
 */

#include "oqs_prov.h"
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/types.h>
#include <openssl/x509.h>

/*  Composite definitions  */

#define COMPOSITE_OID_PREFIX_LEN 26

DECLARE_ASN1_FUNCTIONS(CompositeSignature)

ASN1_NDEF_SEQUENCE(CompositeSignature) =
    {
        ASN1_SIMPLE(CompositeSignature, sig1, ASN1_BIT_STRING),
        ASN1_SIMPLE(CompositeSignature, sig2, ASN1_BIT_STRING),
} ASN1_NDEF_SEQUENCE_END(CompositeSignature)

        IMPLEMENT_ASN1_FUNCTIONS(CompositeSignature)

    /*  Composite Utility  */

    // get the last number on the composite OID
    int get_composite_idx(char *name) {
    const char *s = NULL;
    int i, len, ret = -1, count = 0;

    for (i = 1; i <= get_OQS_OID_CNT(); i += 2) {
        if (!strcmp(get_oqs_oid_alg_list(i), name)) {
            s = get_oqs_oid_alg_list(i - 1);
            break;
        }
    }
    if (s == NULL) {
        return ret;
    }

    len = strlen(s);

    for (i = 0; i < len; i++) {
        if (s[i] == '.') {
            count += 1;
        }
        if (count == 8) { // 8 dots in composite OID
            errno = 0;
            ret = strtol(s + i + 1, NULL, 10);
            if (errno == ERANGE)
                ret = -1;
            break;
        }
    }
    return ret;
}

/* steal from openssl/providers/implementations/encode_decode/encode_key2text.c
 */

#define LABELED_BUF_PRINT_WIDTH 15

static int print_labeled_buf(BIO *out, const char *label,
                             const unsigned char *buf, size_t buflen) {
    size_t i;

    if (BIO_printf(out, "%s\n", label) <= 0)
        return 0;

    for (i = 0; i < buflen; i++) {
        if ((i % LABELED_BUF_PRINT_WIDTH) == 0) {
            if (i > 0 && BIO_printf(out, "\n") <= 0)
                return 0;
            if (BIO_printf(out, "    ") <= 0)
                return 0;
        }

        if (BIO_printf(out, "%02x%s", buf[i], (i == buflen - 1) ? "" : ":") <=
            0)
            return 0;
    }
    if (BIO_printf(out, "\n") <= 0)
        return 0;

    return 1;
}

// this list need to be in order of the last number on the OID from the
// composite, the len of each value is COMPOSITE_OID_PREFIX_LEN
static const unsigned char *composite_OID_prefix[] = {
    /*
     * mldsa44_pss2048
     * id-MLDSA44-RSA2048-PSS-SHA256
     */
    (const unsigned char *)"060B6086480186FA6B50080101",

    /*
     * mldsa44_rsa2048
     * id-MLDSA44-RSA2048-PKCS15-SHA256
     */
    (const unsigned char *)"060B6086480186FA6B50080102",

    /*
     * mldsa44_ed25519
     * id-MLDSA44-Ed25519-SHA512
     */
    (const unsigned char *)"060B6086480186FA6B50080103",

    /*
     * mldsa44_p256
     * id-MLDSA44-ECDSA-P256-SHA256
     */
    (const unsigned char *)"060B6086480186FA6B50080104",

    /*
     * mldsa44_bp256
     * id-MLDSA44-ECDSA-brainpoolP256r1-SHA256
     */
    (const unsigned char *)"060B6086480186FA6B50080105",

    /*
     * mldsa65_pss3072
     * id-MLDSA65-RSA3072-PSS-SHA512
     */
    (const unsigned char *)"060B6086480186FA6B50080106",

    /*
     * mldsa65_rsa3072
     * id-MLDSA65-RSA3072-PKCS15-SHA512
     */
    (const unsigned char *)"060B6086480186FA6B50080107",

    /*
     * mldsa65_p256
     * id-MLDSA65-ECDSA-P256-SHA512
     */
    (const unsigned char *)"060B6086480186FA6B50080108",

    /*
     * mldsa65_bp256
     * id-MLDSA65-ECDSA-brainpoolP256r1-SHA512
     */
    (const unsigned char *)"060B6086480186FA6B50080109",

    /*
     * mldsa65_ed25519
     * id-MLDSA65-Ed25519-SHA512
     */
    (const unsigned char *)"060B6086480186FA6B5008010A",

    /*
     * mldsa87_p384
     * id-MLDSA87-ECDSA-P384-SHA512
     */
    (const unsigned char *)"060B6086480186FA6B5008010B",

    /*
     * mldsa87_bp384
     * id-MLDSA87-ECDSA-brainpoolP384r1-SHA512
     */
    (const unsigned char *)"060B6086480186FA6B5008010C",

    /*
     * mldsa87_ed448
     * id-MLDSA87-Ed448-SHA512
     */
    (const unsigned char *)"060B6086480186FA6B5008010D",

    /*
     * falcon512_p256
     * id-Falon512-ECDSA-P256-SHA256
     */
    (const unsigned char *)"060B6086480186FA6B5008010E",

    /*
     * falcon512_p256
     * id-Falcon512-ECDSA-brainpoolP256r1-SHA256
     */
    (const unsigned char *)"060B6086480186FA6B5008010F",

    /*
     * falcon512_ed25519
     * id-Falcon512-Ed25519-SHA512
     */
    (const unsigned char *)"060B6086480186FA6B50080110",
};

/*put the chars on in into memory on out*/
void composite_prefix_conversion(char *out, const unsigned char *in) {
    int temp;
    for (int i = 0; i < COMPOSITE_OID_PREFIX_LEN / 2; i++) {
        temp = OPENSSL_hexchar2int(in[2 * i]);
        temp = temp * 16;
        temp += OPENSSL_hexchar2int(in[2 * i + 1]);
        out[i] = (unsigned char)temp;
    }
}

/*  SIG functions  */

int oqs_composite_sig_sign(OQSX_KEY *oqsxkey, unsigned char *sig,
                           const unsigned char *tbs, size_t tbslen) {

    unsigned char *buf;
    int i, ret = -1, aux = 0;
    int nid = OBJ_sn2nid(oqsxkey->tls_name);
    size_t classical_sig_len = 0, oqs_sig_len = 0;
    int comp_idx = get_composite_idx(oqsxkey->tls_name);
    if (comp_idx == -1)
        return ret;
    const unsigned char *oid_prefix = composite_OID_prefix[comp_idx - 1];
    char *final_tbs;
    CompositeSignature *compsig = CompositeSignature_new();
    size_t final_tbslen = COMPOSITE_OID_PREFIX_LEN /
                          2; // COMPOSITE_OID_PREFIX_LEN stores the size of
                             // the *char, but the prefix will be on memory,
                             // so each 2 chars will translate into one byte
    unsigned char *tbs_hash;
    OQS_SIG *oqs_key = oqsxkey->oqsx_provider_ctx.oqsx_qs_ctx.sig;
    EVP_PKEY *oqs_key_classic = NULL;
    EVP_PKEY_CTX *classical_ctx_sign = NULL;

    // prepare the pre hash
    for (i = 0; i < oqsxkey->numkeys; i++) {
        char *name;
        char *upcase_name;
        if ((name = get_cmpname(nid, i)) == NULL) {
            ERR_raise(ERR_LIB_USER, ERR_R_FATAL);
            CompositeSignature_free(compsig);
            return ret;
        }
        upcase_name = get_oqsname_fromtls(name);

        if ((upcase_name != 0) &&
                ((!strcmp(upcase_name, OQS_SIG_alg_ml_dsa_65)) ||
                 (!strcmp(upcase_name, OQS_SIG_alg_ml_dsa_87))) ||
            (name[0] == 'e')) {
            aux = 1;
            OPENSSL_free(name);
            break;
        }
        OPENSSL_free(name);
    }
    switch (aux) {
    case 0:
        tbs_hash = OPENSSL_malloc(SHA256_DIGEST_LENGTH);
        SHA256(tbs, tbslen, tbs_hash);
        final_tbslen += SHA256_DIGEST_LENGTH;
        break;
    case 1:
        tbs_hash = OPENSSL_malloc(SHA512_DIGEST_LENGTH);
        SHA512(tbs, tbslen, tbs_hash);
        final_tbslen += SHA512_DIGEST_LENGTH;
        break;
    default:
        ERR_raise(ERR_LIB_USER, ERR_R_FATAL);
        CompositeSignature_free(compsig);
        return ret;
    }
    final_tbs = OPENSSL_malloc(final_tbslen);
    composite_prefix_conversion(final_tbs, oid_prefix);
    memcpy(final_tbs + COMPOSITE_OID_PREFIX_LEN / 2, tbs_hash,
           final_tbslen - COMPOSITE_OID_PREFIX_LEN / 2);
    OPENSSL_free(tbs_hash);

    // sign
    for (i = 0; i < oqsxkey->numkeys; i++) {
        char *name;
        if ((name = get_cmpname(nid, i)) == NULL) {
            ERR_raise(ERR_LIB_USER, ERR_R_FATAL);
            CompositeSignature_free(compsig);
            OPENSSL_free(final_tbs);
            return ret;
        }

        if (get_oqsname_fromtls(name)) { // PQC signing
            oqs_sig_len =
                oqsxkey->oqsx_provider_ctx.oqsx_qs_ctx.sig->length_signature;
            buf = OPENSSL_malloc(oqs_sig_len);
            if (OQS_SIG_sign(oqs_key, buf, &oqs_sig_len,
                             (const unsigned char *)final_tbs, final_tbslen,
                             oqsxkey->comp_privkey[i]) != OQS_SUCCESS) {
                ERR_raise(ERR_LIB_USER, OQSPROV_R_SIGNING_FAILED);
                CompositeSignature_free(compsig);
                OPENSSL_free(final_tbs);
                OPENSSL_free(name);
                OPENSSL_free(buf);
                return ret;
            }
        } else { // sign non PQC key on oqs_key
            oqs_key_classic = oqsxkey->classical_pkey;
            oqs_sig_len = oqsxkey->oqsx_provider_ctx.oqsx_evp_ctx->evp_info
                              ->length_signature;
            buf = OPENSSL_malloc(oqs_sig_len);
            const EVP_MD *classical_md;
            int digest_len;
            unsigned char digest[SHA512_DIGEST_LENGTH]; /* init with max
                                                           length */

            if (name[0] == 'e') { // ed25519 or ed448
                EVP_MD_CTX *evp_ctx = EVP_MD_CTX_new();
                if ((EVP_DigestSignInit(evp_ctx, NULL, NULL, NULL,
                                        oqs_key_classic) <= 0) ||
                    (EVP_DigestSign(evp_ctx, buf, &oqs_sig_len,
                                    (const unsigned char *)final_tbs,
                                    final_tbslen) <= 0)) {
                    ERR_raise(ERR_LIB_USER, ERR_R_FATAL);
                    CompositeSignature_free(compsig);
                    OPENSSL_free(final_tbs);
                    OPENSSL_free(name);
                    EVP_MD_CTX_free(evp_ctx);
                    OPENSSL_free(buf);
                    return ret;
                }
                EVP_MD_CTX_free(evp_ctx);
            } else {
                if ((classical_ctx_sign =
                         EVP_PKEY_CTX_new(oqs_key_classic, NULL)) == NULL ||
                    (EVP_PKEY_sign_init(classical_ctx_sign) <= 0)) {
                    ERR_raise(ERR_LIB_USER, ERR_R_FATAL);
                    CompositeSignature_free(compsig);
                    OPENSSL_free(final_tbs);
                    OPENSSL_free(name);
                    OPENSSL_free(buf);
                    return ret;
                }

                if (!strncmp(name, "pss", 3)) {
                    int salt;
                    const EVP_MD *pss_mgf1;
                    if (!strncmp(name, "pss3072", 7)) {
                        salt = 64;
                        pss_mgf1 = EVP_sha512();
                    } else {
                        if (!strncmp(name, "pss2048", 7)) {
                            salt = 32;
                            pss_mgf1 = EVP_sha256();
                        } else {
                            ERR_raise(ERR_LIB_USER, ERR_R_FATAL);
                            CompositeSignature_free(compsig);
                            OPENSSL_free(final_tbs);
                            OPENSSL_free(name);
                            OPENSSL_free(buf);
                            return ret;
                        }
                    }
                    if ((EVP_PKEY_CTX_set_rsa_padding(
                             classical_ctx_sign, RSA_PKCS1_PSS_PADDING) <= 0) ||
                        (EVP_PKEY_CTX_set_rsa_pss_saltlen(classical_ctx_sign,
                                                          salt) <= 0) ||
                        (EVP_PKEY_CTX_set_rsa_mgf1_md(classical_ctx_sign,
                                                      pss_mgf1) <= 0)) {
                        ERR_raise(ERR_LIB_USER, ERR_R_FATAL);
                        CompositeSignature_free(compsig);
                        OPENSSL_free(final_tbs);
                        OPENSSL_free(name);
                        OPENSSL_free(buf);
                        return ret;
                    }
                } else if (oqsxkey->oqsx_provider_ctx.oqsx_evp_ctx->evp_info
                               ->keytype == EVP_PKEY_RSA) {
                    if (EVP_PKEY_CTX_set_rsa_padding(classical_ctx_sign,
                                                     RSA_PKCS1_PADDING) <= 0) {
                        ERR_raise(ERR_LIB_USER, ERR_R_FATAL);
                        CompositeSignature_free(compsig);
                        OPENSSL_free(final_tbs);
                        OPENSSL_free(name);
                        OPENSSL_free(buf);
                        return ret;
                    }
                }
                if (comp_idx < 6) {
                    classical_md = EVP_sha256();
                    digest_len = SHA256_DIGEST_LENGTH;
                    SHA256((const unsigned char *)final_tbs, final_tbslen,
                           (unsigned char *)&digest);
                } else {
                    classical_md = EVP_sha512();
                    digest_len = SHA512_DIGEST_LENGTH;
                    SHA512((const unsigned char *)final_tbs, final_tbslen,
                           (unsigned char *)&digest);
                }

                if ((EVP_PKEY_CTX_set_signature_md(classical_ctx_sign,
                                                   classical_md) <= 0) ||
                    (EVP_PKEY_sign(classical_ctx_sign, buf, &oqs_sig_len,
                                   digest, digest_len) <= 0)) {
                    ERR_raise(ERR_LIB_USER, ERR_R_FATAL);
                    CompositeSignature_free(compsig);
                    OPENSSL_free(final_tbs);
                    OPENSSL_free(name);
                    OPENSSL_free(buf);
                    return ret;
                }

                if (oqs_sig_len > oqsxkey->oqsx_provider_ctx.oqsx_evp_ctx
                                      ->evp_info->length_signature) {
                    /* sig is bigger than expected */
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_BUFFER_LENGTH_WRONG);
                    CompositeSignature_free(compsig);
                    OPENSSL_free(final_tbs);
                    OPENSSL_free(name);
                    OPENSSL_free(buf);
                    return ret;
                }
            }
        }

        if (i == 0) {
            compsig->sig1->data = OPENSSL_memdup(buf, oqs_sig_len);
            compsig->sig1->length = oqs_sig_len;
            compsig->sig1->flags = 8; // set as 8 to not check for unused bits
        } else {
            compsig->sig2->data = OPENSSL_memdup(buf, oqs_sig_len);
            compsig->sig2->length = oqs_sig_len;
            compsig->sig2->flags = 8; // set as 8 to not check for unused bits
        }

        OPENSSL_free(buf);
        OPENSSL_free(name);
    }
    oqs_sig_len = i2d_CompositeSignature(compsig, &sig);

    CompositeSignature_free(compsig);
    OPENSSL_free(final_tbs);
    return oqs_sig_len;
}

int oqs_composite_sig_verify(OQSX_KEY *oqsxkey, const unsigned char *sig,
                             size_t siglen, const unsigned char *tbs,
                             size_t tbslen) {

    CompositeSignature *compsig;
    int i, ret = -1;
    int nid = OBJ_sn2nid(oqsxkey->tls_name);
    int comp_idx = get_composite_idx(oqsxkey->tls_name);
    if (comp_idx == -1)
        return ret;
    unsigned char *buf;
    size_t buf_len;
    const unsigned char *oid_prefix = composite_OID_prefix[comp_idx - 1];
    char *final_tbs;
    size_t final_tbslen = COMPOSITE_OID_PREFIX_LEN / 2;
    int aux = 0;
    unsigned char *tbs_hash;
    OQS_SIG *oqs_key = oqsxkey->oqsx_provider_ctx.oqsx_qs_ctx.sig;
    EVP_PKEY_CTX *ctx_verify = NULL;

    if ((compsig = d2i_CompositeSignature(NULL, &sig, siglen)) == NULL) {
        ERR_raise(ERR_LIB_USER, OQSPROV_R_VERIFY_ERROR);
        CompositeSignature_free(compsig);
        return ret;
    }

    // prepare the pre hash
    for (i = 0; i < oqsxkey->numkeys; i++) {
        char *name;
        char *upcase_name;
        if ((name = get_cmpname(nid, i)) == NULL) {
            ERR_raise(ERR_LIB_USER, ERR_R_FATAL);
            CompositeSignature_free(compsig);
            return ret;
        }
        upcase_name = get_oqsname_fromtls(name);

        if ((upcase_name != 0) &&
                ((!strcmp(upcase_name, OQS_SIG_alg_ml_dsa_65)) ||
                 (!strcmp(upcase_name, OQS_SIG_alg_ml_dsa_87))) ||
            (name[0] == 'e')) {
            aux = 1;
            OPENSSL_free(name);
            break;
        }
        OPENSSL_free(name);
    }
    switch (aux) {
    case 0:
        tbs_hash = OPENSSL_malloc(SHA256_DIGEST_LENGTH);
        SHA256(tbs, tbslen, tbs_hash);
        final_tbslen += SHA256_DIGEST_LENGTH;
        break;
    case 1:
        tbs_hash = OPENSSL_malloc(SHA512_DIGEST_LENGTH);
        SHA512(tbs, tbslen, tbs_hash);
        final_tbslen += SHA512_DIGEST_LENGTH;
        break;
    default:
        ERR_raise(ERR_LIB_USER, ERR_R_FATAL);
        CompositeSignature_free(compsig);
        return ret;
    }
    final_tbs = OPENSSL_malloc(final_tbslen);
    composite_prefix_conversion(final_tbs, oid_prefix);
    memcpy(final_tbs + COMPOSITE_OID_PREFIX_LEN / 2, tbs_hash,
           final_tbslen - COMPOSITE_OID_PREFIX_LEN / 2);
    OPENSSL_free(tbs_hash);

    // verify
    for (i = 0; i < oqsxkey->numkeys; i++) {
        if (i == 0) {
            buf = compsig->sig1->data;
            buf_len = compsig->sig1->length;
        } else {
            buf = compsig->sig2->data;
            buf_len = compsig->sig2->length;
        }

        char *name;
        if ((name = get_cmpname(nid, i)) == NULL) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_VERIFY_ERROR);
            CompositeSignature_free(compsig);
            OPENSSL_free(final_tbs);
            return ret;
        }

        if (get_oqsname_fromtls(name)) {
            if (OQS_SIG_verify(oqs_key, (const unsigned char *)final_tbs,
                               final_tbslen, buf, buf_len,
                               oqsxkey->comp_pubkey[i]) != OQS_SUCCESS) {
                ERR_raise(ERR_LIB_USER, OQSPROV_R_VERIFY_ERROR);
                OPENSSL_free(name);
                CompositeSignature_free(compsig);
                OPENSSL_free(final_tbs);
                return ret;
            }
        } else {
            const EVP_MD *classical_md;
            int digest_len;
            int aux;
            unsigned char digest[SHA512_DIGEST_LENGTH]; /* init with max
                                                           length */

            if (name[0] == 'e') { // ed25519 or ed448
                EVP_MD_CTX *evp_ctx = EVP_MD_CTX_new();
                if ((EVP_DigestVerifyInit(evp_ctx, NULL, NULL, NULL,
                                          oqsxkey->classical_pkey) <= 0) ||
                    (EVP_DigestVerify(evp_ctx, buf, buf_len,
                                      (const unsigned char *)final_tbs,
                                      final_tbslen) <= 0)) {
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_VERIFY_ERROR);
                    OPENSSL_free(name);
                    EVP_MD_CTX_free(evp_ctx);
                    CompositeSignature_free(compsig);
                    OPENSSL_free(final_tbs);
                    return ret;
                }
                EVP_MD_CTX_free(evp_ctx);
            } else {
                if (((ctx_verify = EVP_PKEY_CTX_new(oqsxkey->classical_pkey,
                                                    NULL)) == NULL) ||
                    (EVP_PKEY_verify_init(ctx_verify) <= 0)) {
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_VERIFY_ERROR);
                    OPENSSL_free(name);
                    CompositeSignature_free(compsig);
                    OPENSSL_free(final_tbs);
                    return ret;
                }
                if (!strncmp(name, "pss", 3)) {
                    int salt;
                    const EVP_MD *pss_mgf1;
                    if (!strncmp(name, "pss3072", 7)) {
                        salt = 64;
                        pss_mgf1 = EVP_sha512();
                    } else {
                        if (!strncmp(name, "pss2048", 7)) {
                            salt = 32;
                            pss_mgf1 = EVP_sha256();
                        } else {
                            ERR_raise(ERR_LIB_USER, OQSPROV_R_VERIFY_ERROR);
                            OPENSSL_free(name);
                            CompositeSignature_free(compsig);
                            OPENSSL_free(final_tbs);
                            return ret;
                        }
                    }
                    if ((EVP_PKEY_CTX_set_rsa_padding(
                             ctx_verify, RSA_PKCS1_PSS_PADDING) <= 0) ||
                        (EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx_verify, salt) <=
                         0) ||
                        (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx_verify, pss_mgf1) <=
                         0)) {
                        ERR_raise(ERR_LIB_USER, OQSPROV_R_WRONG_PARAMETERS);
                        OPENSSL_free(name);
                        CompositeSignature_free(compsig);
                        OPENSSL_free(final_tbs);
                        return ret;
                    }
                } else if (oqsxkey->oqsx_provider_ctx.oqsx_evp_ctx->evp_info
                               ->keytype == EVP_PKEY_RSA) {
                    if (EVP_PKEY_CTX_set_rsa_padding(ctx_verify,
                                                     RSA_PKCS1_PADDING) <= 0) {
                        ERR_raise(ERR_LIB_USER, OQSPROV_R_WRONG_PARAMETERS);
                        OPENSSL_free(name);
                        CompositeSignature_free(compsig);
                        OPENSSL_free(final_tbs);
                        return ret;
                    }
                }
                if (comp_idx < 6) {
                    classical_md = EVP_sha256();
                    digest_len = SHA256_DIGEST_LENGTH;
                    SHA256((const unsigned char *)final_tbs, final_tbslen,
                           (unsigned char *)&digest);
                } else {
                    classical_md = EVP_sha512();
                    digest_len = SHA512_DIGEST_LENGTH;
                    SHA512((const unsigned char *)final_tbs, final_tbslen,
                           (unsigned char *)&digest);
                }

                if ((EVP_PKEY_CTX_set_signature_md(ctx_verify, classical_md) <=
                     0) ||
                    (EVP_PKEY_verify(ctx_verify, buf, buf_len, digest,
                                     digest_len) <= 0)) {
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_VERIFY_ERROR);
                    OPENSSL_free(name);
                    CompositeSignature_free(compsig);
                    OPENSSL_free(final_tbs);
                    return ret;
                }
            }
        }

        OPENSSL_free(name);
    }
    CompositeSignature_free(compsig);
    OPENSSL_free(final_tbs);
    ret = 0;
    return ret;
}

/*  ENCODER KEY 2 ANY functions  */

int oqsx_composite_spki_pub_to_der(const OQSX_KEY *oqsxkey,
                                   unsigned char **pder) {
    STACK_OF(ASN1_TYPE) *sk = NULL;
    unsigned char *keyblob, *buf;
    int keybloblen, nid, buflen = 0;
    ASN1_OCTET_STRING oct;

    if ((sk = sk_ASN1_TYPE_new_null()) == NULL)
        return -1;
    ASN1_TYPE **aType = OPENSSL_malloc(oqsxkey->numkeys * sizeof(ASN1_TYPE *));
    ASN1_BIT_STRING **aString =
        OPENSSL_malloc(oqsxkey->numkeys * sizeof(ASN1_BIT_STRING *));
    unsigned char **temp =
        OPENSSL_malloc(oqsxkey->numkeys * sizeof(unsigned char *));
    size_t *templen = OPENSSL_malloc(oqsxkey->numkeys * sizeof(size_t));
    int i;

    for (i = 0; i < oqsxkey->numkeys; i++) {
        aType[i] = ASN1_TYPE_new();
        aString[i] = ASN1_BIT_STRING_new();
        temp[i] = NULL;

        buflen = oqsxkey->pubkeylen_cmp[i];
        buf = OPENSSL_secure_malloc(buflen);
        memcpy(buf, oqsxkey->comp_pubkey[i], buflen);

        oct.data = buf;
        oct.length = buflen;
        oct.flags = 8;
        templen[i] = i2d_ASN1_BIT_STRING(&oct, &temp[i]);
        ASN1_STRING_set(aString[i], temp[i], templen[i]);
        ASN1_TYPE_set1(aType[i], V_ASN1_SEQUENCE, aString[i]);

        if (!sk_ASN1_TYPE_push(sk, aType[i])) {
            for (int j = 0; j <= i; j++) {
                OPENSSL_cleanse(aString[j]->data, aString[j]->length);
                ASN1_BIT_STRING_free(aString[j]);
                OPENSSL_cleanse(aType[j]->value.sequence->data,
                                aType[j]->value.sequence->length);
                OPENSSL_clear_free(temp[j], templen[j]);
            }

            sk_ASN1_TYPE_pop_free(sk, &ASN1_TYPE_free);
            OPENSSL_secure_clear_free(buf, buflen);
            OPENSSL_free(aType);
            OPENSSL_free(aString);
            OPENSSL_free(temp);
            OPENSSL_free(templen);
            return -1;
        }
        OPENSSL_secure_clear_free(buf, buflen);
    }
    keybloblen = i2d_ASN1_SEQUENCE_ANY(sk, pder);

    for (i = 0; i < oqsxkey->numkeys; i++) {
        OPENSSL_cleanse(aString[i]->data, aString[i]->length);
        ASN1_BIT_STRING_free(aString[i]);
        OPENSSL_cleanse(aType[i]->value.sequence->data,
                        aType[i]->value.sequence->length);
        OPENSSL_clear_free(temp[i], templen[i]);
    }

    sk_ASN1_TYPE_pop_free(sk, &ASN1_TYPE_free);
    OPENSSL_free(aType);
    OPENSSL_free(aString);
    OPENSSL_free(temp);
    OPENSSL_free(templen);

    return keybloblen;
}

int oqsx_composite_pki_priv_to_der(const OQSX_KEY *oqsxkey,
                                   unsigned char **pder) {
    int keybloblen, nid;
    STACK_OF(ASN1_TYPE) *sk = NULL;
    char *name;
    ASN1_TYPE **aType = OPENSSL_malloc(oqsxkey->numkeys * sizeof(ASN1_TYPE *));
    ASN1_OCTET_STRING **aString =
        OPENSSL_malloc(oqsxkey->numkeys * sizeof(ASN1_OCTET_STRING *));
    unsigned char **temp =
        OPENSSL_malloc(oqsxkey->numkeys * sizeof(unsigned char *));
    unsigned char *ed_internal;
    size_t *templen = OPENSSL_malloc(oqsxkey->numkeys * sizeof(size_t)),
           ed_internallen;
    PKCS8_PRIV_KEY_INFO *p8inf_internal = NULL;
    sk = sk_ASN1_TYPE_new_null();
    int i;
    uint32_t buflen = 0;
    ASN1_OCTET_STRING oct;
    unsigned char *buf = NULL;

    if (!sk || !templen || !aType || !aString || !temp) {
        OPENSSL_free(aType);
        OPENSSL_free(aString);
        OPENSSL_free(temp);
        OPENSSL_free(templen);
        if (sk) {
            sk_ASN1_TYPE_pop_free(sk, ASN1_TYPE_free);
        }
        return -1;
    }

    for (i = 0; i < oqsxkey->numkeys; i++) {
        aType[i] = ASN1_TYPE_new();
        aString[i] = ASN1_OCTET_STRING_new();
        p8inf_internal = PKCS8_PRIV_KEY_INFO_new();
        temp[i] = NULL;
        int version;
        void *pval;

        if ((name = get_cmpname(OBJ_sn2nid(oqsxkey->tls_name), i)) == NULL) {
            for (int j = 0; j <= i; j++) {
                OPENSSL_cleanse(aString[j]->data, aString[j]->length);
                ASN1_OCTET_STRING_free(aString[j]);
                OPENSSL_cleanse(aType[j]->value.sequence->data,
                                aType[j]->value.sequence->length);
                if (j < i)
                    OPENSSL_clear_free(temp[j], templen[j]);
            }

            if (sk_ASN1_TYPE_num(sk) != -1)
                sk_ASN1_TYPE_pop_free(sk, &ASN1_TYPE_free);
            else
                ASN1_TYPE_free(aType[i]);

            OPENSSL_free(aType);
            OPENSSL_free(aString);
            OPENSSL_free(temp);
            OPENSSL_free(templen);
            PKCS8_PRIV_KEY_INFO_free(p8inf_internal);
            return -1;
        }

        if (get_oqsname_fromtls(name) == 0) {
            nid = oqsxkey->oqsx_provider_ctx.oqsx_evp_ctx->evp_info->keytype;
            if (nid == EVP_PKEY_RSA) { // get the RSA real key size
                unsigned char *enc_len = (unsigned char *)OPENSSL_strndup(
                    oqsxkey->comp_privkey[i], 4);
                OPENSSL_cleanse(enc_len, 2);
                DECODE_UINT32(buflen, enc_len);
                buflen += 4;
                OPENSSL_free(enc_len);
                if (buflen > oqsxkey->privkeylen_cmp[i]) {
                    for (int j = 0; j <= i; j++) {
                        OPENSSL_cleanse(aString[j]->data, aString[j]->length);
                        ASN1_OCTET_STRING_free(aString[j]);
                        OPENSSL_cleanse(aType[j]->value.sequence->data,
                                        aType[j]->value.sequence->length);
                        if (j < i)
                            OPENSSL_clear_free(temp[j], templen[j]);
                    }

                    if (sk_ASN1_TYPE_num(sk) != -1)
                        sk_ASN1_TYPE_pop_free(sk, &ASN1_TYPE_free);
                    else
                        ASN1_TYPE_free(aType[i]);

                    OPENSSL_free(aType);
                    OPENSSL_free(aString);
                    OPENSSL_free(temp);
                    OPENSSL_free(templen);
                    PKCS8_PRIV_KEY_INFO_free(p8inf_internal);
                    OPENSSL_free(name);
                    return -1;
                }
            } else
                buflen = oqsxkey->privkeylen_cmp[i];
        } else {
            nid = OBJ_sn2nid(name);
            buflen = oqsxkey->privkeylen_cmp[i] + oqsxkey->pubkeylen_cmp[i];
        }

        buf = OPENSSL_secure_malloc(buflen);
        if (buf == NULL) {
            for (int j = 0; j <= i; j++) {
                OPENSSL_cleanse(aString[j]->data, aString[j]->length);
                ASN1_OCTET_STRING_free(aString[j]);
                OPENSSL_cleanse(aType[j]->value.sequence->data,
                                aType[j]->value.sequence->length);
                if (j < i)
                    OPENSSL_clear_free(temp[j], templen[j]);
            }

            if (sk_ASN1_TYPE_num(sk) != -1)
                sk_ASN1_TYPE_pop_free(sk, &ASN1_TYPE_free);
            else
                ASN1_TYPE_free(aType[i]);

            OPENSSL_free(aType);
            OPENSSL_free(aString);
            OPENSSL_free(temp);
            OPENSSL_free(templen);
            PKCS8_PRIV_KEY_INFO_free(p8inf_internal);
            OPENSSL_free(name);
            ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
            return -1;
        }
        if (get_oqsname_fromtls(name) !=
            0) { // include pubkey in privkey for PQC
            memcpy(buf, oqsxkey->comp_privkey[i], oqsxkey->privkeylen_cmp[i]);
            memcpy(buf + oqsxkey->privkeylen_cmp[i], oqsxkey->comp_pubkey[i],
                   oqsxkey->pubkeylen_cmp[i]);
        } else {
            memcpy(buf, oqsxkey->comp_privkey[i],
                   buflen); // buflen for classical (RSA)
                            // might be different from
                            // oqsxkey->privkeylen_cmp
        }

        if (nid == EVP_PKEY_EC) { // add the curve OID with the ECPubkey OID
            version = V_ASN1_OBJECT;
            pval = OBJ_nid2obj(
                oqsxkey->oqsx_provider_ctx.oqsx_evp_ctx->evp_info->nid);
        } else {
            version = V_ASN1_UNDEF;
            pval = NULL;
        }
        if (nid == EVP_PKEY_ED25519 || nid == EVP_PKEY_ED448) {
            oct.data = buf;
            oct.length = buflen;
            oct.flags = 0;
            ed_internal = NULL;

            ed_internallen = i2d_ASN1_OCTET_STRING(&oct, &ed_internal);
            if (ed_internallen < 0) {
                for (int j = 0; j <= i; j++) {
                    OPENSSL_cleanse(aString[j]->data, aString[j]->length);
                    ASN1_OCTET_STRING_free(aString[j]);
                    OPENSSL_cleanse(aType[j]->value.sequence->data,
                                    aType[j]->value.sequence->length);
                    OPENSSL_clear_free(temp[j], templen[j]);
                }

                sk_ASN1_TYPE_pop_free(sk, &ASN1_TYPE_free);
                OPENSSL_free(name);
                OPENSSL_free(aType);
                OPENSSL_free(aString);
                OPENSSL_free(temp);
                OPENSSL_free(templen);
                OPENSSL_cleanse(buf,
                                buflen); // buf is part of p8inf_internal so
                                         // we cant free now, we cleanse it
                                         // to remove pkey from memory
                PKCS8_PRIV_KEY_INFO_free(p8inf_internal); // this also free buf
                return -1;
            }

            if (!PKCS8_pkey_set0(p8inf_internal, OBJ_nid2obj(nid), 0, version,
                                 pval, ed_internal, ed_internallen)) {
                for (int j = 0; j <= i; j++) {
                    OPENSSL_cleanse(aString[j]->data, aString[j]->length);
                    ASN1_OCTET_STRING_free(aString[j]);
                    OPENSSL_cleanse(aType[j]->value.sequence->data,
                                    aType[j]->value.sequence->length);
                    OPENSSL_clear_free(temp[j], templen[j]);
                }

                sk_ASN1_TYPE_pop_free(sk, &ASN1_TYPE_free);
                OPENSSL_free(name);
                OPENSSL_free(aType);
                OPENSSL_free(aString);
                OPENSSL_free(temp);
                OPENSSL_free(templen);
                OPENSSL_secure_clear_free(buf, buflen);
                OPENSSL_cleanse(ed_internal, ed_internallen);
                PKCS8_PRIV_KEY_INFO_free(
                    p8inf_internal); // this also free ed_internal
                return -1;
            }

        } else {
            if (!PKCS8_pkey_set0(p8inf_internal, OBJ_nid2obj(nid), 0, version,
                                 pval, buf, buflen)) {
                for (int j = 0; j <= i; j++) {
                    OPENSSL_cleanse(aString[j]->data, aString[j]->length);
                    ASN1_OCTET_STRING_free(aString[j]);
                    OPENSSL_cleanse(aType[j]->value.sequence->data,
                                    aType[j]->value.sequence->length);
                    OPENSSL_clear_free(temp[j], templen[j]);
                }

                sk_ASN1_TYPE_pop_free(sk, &ASN1_TYPE_free);
                OPENSSL_free(name);
                OPENSSL_free(aType);
                OPENSSL_free(aString);
                OPENSSL_free(temp);
                OPENSSL_free(templen);
                OPENSSL_cleanse(buf,
                                buflen); // buf is part of p8inf_internal so
                                         // we cant free now, we cleanse it
                                         // to remove pkey from memory
                PKCS8_PRIV_KEY_INFO_free(p8inf_internal); // this also free buf
                return -1;
            }
        }
        templen[i] =
            i2d_PKCS8_PRIV_KEY_INFO(p8inf_internal,
                                    &temp[i]); // create the privkey info
                                               // for each individual key
        ASN1_STRING_set(aString[i], temp[i],
                        templen[i]); // add privkey info as ASN1_STRING
        ASN1_TYPE_set1(aType[i], V_ASN1_SEQUENCE,
                       aString[i]); // add the ASN1_STRING into a ANS1_TYPE
                                    // so it can be added into the stack

        if (!sk_ASN1_TYPE_push(sk, aType[i])) {
            for (int j = 0; j <= i; j++) {
                OPENSSL_cleanse(aString[j]->data, aString[j]->length);
                ASN1_OCTET_STRING_free(aString[j]);
                OPENSSL_cleanse(aType[j]->value.sequence->data,
                                aType[j]->value.sequence->length);
                OPENSSL_clear_free(temp[j], templen[j]);
            }

            sk_ASN1_TYPE_pop_free(sk, &ASN1_TYPE_free);
            OPENSSL_free(name);
            OPENSSL_free(aType);
            OPENSSL_free(aString);
            OPENSSL_free(temp);
            OPENSSL_free(templen);
            OPENSSL_cleanse(buf,
                            buflen); // buf is part of p8inf_internal so we
                                     // cant free now, we cleanse it to
                                     // remove pkey from memory
            if (nid == EVP_PKEY_ED25519 || nid == EVP_PKEY_ED448) {
                OPENSSL_cleanse(ed_internal, ed_internallen);
                OPENSSL_secure_free(buf); // in this case the ed_internal is
                                          // freed from the pkcs8_free instead
                                          // of buf, so we need to free buf here
            }
            PKCS8_PRIV_KEY_INFO_free(
                p8inf_internal); // this also free buf or ed_internal
            return -1;
        }
        OPENSSL_free(name);

        OPENSSL_cleanse(buf, buflen);
        if (nid == EVP_PKEY_ED25519 || nid == EVP_PKEY_ED448) {
            OPENSSL_cleanse(ed_internal, ed_internallen);
            OPENSSL_secure_free(buf); // in this case the ed_internal is
                                      // freed from the pkcs8_free instead
                                      // of buf, so we need to free buf here
        }
        PKCS8_PRIV_KEY_INFO_free(p8inf_internal);
    }
    keybloblen = i2d_ASN1_SEQUENCE_ANY(sk, pder);

    for (i = 0; i < oqsxkey->numkeys; i++) {
        OPENSSL_cleanse(aString[i]->data, aString[i]->length);
        ASN1_OCTET_STRING_free(aString[i]);
        OPENSSL_cleanse(aType[i]->value.sequence->data,
                        aType[i]->value.sequence->length);
        OPENSSL_clear_free(temp[i], templen[i]);
    }

    sk_ASN1_TYPE_pop_free(sk, &ASN1_TYPE_free);
    OPENSSL_free(aType);
    OPENSSL_free(aString);
    OPENSSL_free(temp);
    OPENSSL_free(templen);

    return keybloblen;
}

int oqsx_composite_to_text(BIO *out, OQSX_KEY *okey) {
    char *name;
    char label[200];
    int i;

    if (okey->privkey) {
        uint32_t privlen = 0;
        for (i = 0; i < okey->numkeys; i++) {
            if ((name = get_cmpname(OBJ_sn2nid(okey->tls_name), i)) == NULL) {
                ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_KEY);
                return 0;
            }
            sprintf(label, "%s key material:", name);

            if (get_oqsname_fromtls(name) == 0 // classical key
                && okey->oqsx_provider_ctx.oqsx_evp_ctx->evp_info->keytype ==
                       EVP_PKEY_RSA) { // get the RSA real key size
                unsigned char *enc_len =
                    (unsigned char *)OPENSSL_strndup(okey->comp_privkey[i], 4);
                OPENSSL_cleanse(enc_len, 2);
                DECODE_UINT32(privlen, enc_len);
                privlen += 4;
                OPENSSL_free(enc_len);
                if (privlen > okey->privkeylen_cmp[i]) {
                    OPENSSL_free(name);
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    return 0;
                }
            } else
                privlen = okey->privkeylen_cmp[i];
            if (!print_labeled_buf(out, label, okey->comp_privkey[i], privlen))
                return 0;

            OPENSSL_free(name);
        }
        return 1;
    } else if (okey->pubkey) {
        for (i = 0; i < okey->numkeys; i++) {
            if ((name = get_cmpname(OBJ_sn2nid(okey->tls_name), i)) == NULL) {
                ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_KEY);
                return 0;
            }
            sprintf(label, "%s key material:", name);

            if (!print_labeled_buf(out, label, okey->comp_pubkey[i],
                                   okey->pubkeylen_cmp[i]))
                return 0;

            OPENSSL_free(name);
        }
        return 1;
    }
    return 0;
}

/*  OQS PROV KEY functions  */

OQSX_KEY *oqsx_composite_key_op(OQSX_KEY *key, const unsigned char *p,
                                int plen) {
    uint32_t privlen = 0;
    size_t publen = 0;
    size_t previous_privlen = 0;
    size_t previous_publen = 0;
    size_t temp_pub_len, temp_priv_len;
    char *temp_priv, *temp_pub;
    int pqc_pub_enc = 0;
    int i;

    // check if key is the right size
    for (i = 0; i < key->numkeys; i++) {
        char *name;
        if ((name = get_cmpname(OBJ_sn2nid(key->tls_name), i)) == NULL) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
            oqsx_key_free(key);
            return NULL;
        }
        privlen = key->privkeylen_cmp[i];
        if (get_oqsname_fromtls(name) == 0) { // classical key
            publen = 0;
        } else {                            // PQC key
            publen = key->pubkeylen_cmp[i]; // pubkey in
                                            // PQC privkey
                                            // is OPTIONAL
        }
        previous_privlen += privlen;
        previous_publen += publen;
        OPENSSL_free(name);
    }
    if (previous_privlen != plen) {
        // is ok, PQC pubkey might be in privkey
        pqc_pub_enc = 1;
        if (previous_privlen + previous_publen != plen) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
            oqsx_key_free(key);
            return NULL;
        }
        if (oqsx_key_allocate_keymaterial(key, 0)) {
            ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
            oqsx_key_free(key);
            return NULL;
        }
    }
    if (oqsx_key_allocate_keymaterial(key, 1)) {
        ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
        oqsx_key_free(key);
        return NULL;
    }
    temp_priv_len = previous_privlen;
    temp_pub_len = previous_publen;
    temp_priv = OPENSSL_secure_zalloc(temp_priv_len);
    temp_pub = OPENSSL_secure_zalloc(temp_pub_len);
    previous_privlen = 0;
    previous_publen = 0;
    for (i = 0; i < key->numkeys; i++) {
        size_t classic_publen = 0;
        char *name;
        if ((name = get_cmpname(OBJ_sn2nid(key->tls_name), i)) == NULL) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
            OPENSSL_secure_clear_free(temp_priv, temp_priv_len);
            OPENSSL_secure_clear_free(temp_pub, temp_pub_len);
            oqsx_key_free(key);
            return NULL;
        }
        if (get_oqsname_fromtls(name) == 0) { // classical key
            publen = 0;                       // no pubkey encoded with privkey
                                              // on classical keys. will
                                              // recreate the pubkey later
            if (key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info->keytype ==
                EVP_PKEY_RSA) { // get the RSA real key size
                if (previous_privlen + previous_publen + 4 > plen) {
                    OPENSSL_free(name);
                    OPENSSL_secure_clear_free(temp_priv, temp_priv_len);
                    OPENSSL_secure_clear_free(temp_pub, temp_pub_len);
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    oqsx_key_free(key);
                    return NULL;
                }
                unsigned char *enc_len = (unsigned char *)OPENSSL_strndup(
                    (const char *)(p + previous_privlen + previous_publen), 4);
                OPENSSL_cleanse(enc_len, 2);
                DECODE_UINT32(privlen, enc_len);
                privlen += 4;
                OPENSSL_free(enc_len);
                if (privlen > key->privkeylen_cmp[i]) {
                    OPENSSL_free(name);
                    OPENSSL_secure_clear_free(temp_priv, temp_priv_len);
                    OPENSSL_secure_clear_free(temp_pub, temp_pub_len);
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    oqsx_key_free(key);
                    return NULL;
                }
                key->privkeylen_cmp[i] = privlen;
            } else
                privlen = key->privkeylen_cmp[i];
        } else { // PQC key
            privlen = key->privkeylen_cmp[i];
            if (pqc_pub_enc)
                publen = key->pubkeylen_cmp[i];
            else
                publen = 0;
        }
        if (previous_privlen + previous_publen + privlen + publen > plen) {
            OPENSSL_free(name);
            OPENSSL_secure_clear_free(temp_priv, temp_priv_len);
            OPENSSL_secure_clear_free(temp_pub, temp_pub_len);
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
            oqsx_key_free(key);
            return NULL;
        }
        memcpy(temp_priv + previous_privlen,
               p + previous_privlen + previous_publen, privlen);
        memcpy(temp_pub + previous_publen,
               p + privlen + previous_privlen + previous_publen, publen);
        previous_privlen += privlen;
        previous_publen += publen;
        OPENSSL_free(name);
    }
    memcpy(key->privkey, temp_priv, previous_privlen);
    memcpy(key->pubkey, temp_pub, previous_publen);
    OPENSSL_secure_clear_free(temp_priv, temp_priv_len);
    OPENSSL_secure_clear_free(temp_pub, temp_pub_len);

    return key;
}

int oqsx_composite_key_recreate_classickey(OQSX_KEY *key, oqsx_key_op_t op) {
    int i;
    if (op == KEY_OP_PUBLIC) {
        for (i = 0; i < key->numkeys; i++) {
            char *name;
            if ((name = get_cmpname(OBJ_sn2nid(key->tls_name), i)) == NULL) {
                ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                return 0;
            }
            const unsigned char *enc_pubkey = key->comp_pubkey[i];

            if (get_oqsname_fromtls(name) == 0) {
                if (!key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info
                         ->raw_key_support) {
                    EVP_PKEY *npk = EVP_PKEY_new();
                    if (key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info
                            ->keytype != EVP_PKEY_RSA) {
                        npk = setECParams(
                            npk,
                            key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info->nid);
                    }
                    key->classical_pkey = d2i_PublicKey(
                        key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info->keytype,
                        &npk, &enc_pubkey, key->pubkeylen_cmp[i]);
                } else
                    key->classical_pkey = EVP_PKEY_new_raw_public_key(
                        key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info->keytype,
                        NULL, enc_pubkey, key->pubkeylen_cmp[i]);
                if (!key->classical_pkey) {
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    OPENSSL_free(name);
                    return 0;
                }
            }
            OPENSSL_free(name);
        }
    }

    if (op == KEY_OP_PRIVATE) {
        for (i = 0; i < key->numkeys; i++) {
            char *name;
            if ((name = get_cmpname(OBJ_sn2nid(key->tls_name), i)) == NULL) {
                ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                return 0;
            }
            if (get_oqsname_fromtls(name) == 0) {
                const unsigned char *enc_privkey = key->comp_privkey[i];
                if (!key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info
                         ->raw_key_support) {
                    EVP_PKEY *npk;
                    key->classical_pkey = d2i_PrivateKey(
                        key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info->keytype,
                        NULL, &enc_privkey, key->privkeylen_cmp[i]);
                } else {
                    key->classical_pkey = EVP_PKEY_new_raw_private_key(
                        key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info->keytype,
                        NULL, enc_privkey, key->privkeylen_cmp[i]);
                }
                if (!key->classical_pkey) {
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    OPENSSL_free(name);
                    return 0;
                }
                if (!key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info
                         ->raw_key_support) {
                    unsigned char *comp_pubkey = key->comp_pubkey[i];
                    int pubkeylen =
                        i2d_PublicKey(key->classical_pkey, &comp_pubkey);
                    if (pubkeylen != key->oqsx_provider_ctx.oqsx_evp_ctx
                                         ->evp_info->length_public_key) {
                        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                        OPENSSL_free(name);
                        return 0;
                    }
                } else {
                    size_t pubkeylen = key->pubkeylen_cmp[i];
                    int ret = EVP_PKEY_get_raw_public_key(
                        key->classical_pkey, key->comp_pubkey[i], &pubkeylen);
                    if (ret <= 0) {
                        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                        OPENSSL_free(name);
                        return 0;
                    }
                }
            }
            OPENSSL_free(name);
        }
    }
    return 1;
}

int oqsx_composite_key_set_composites(OQSX_KEY *key) {
    int i;
    int privlen = 0;
    int publen = 0;
    for (i = 0; i < key->numkeys; i++) {
        if (key->privkey) {
            key->comp_privkey[i] = (char *)key->privkey + privlen;
            privlen += key->privkeylen_cmp[i];
        } else {
            key->comp_privkey[i] = NULL;
        }
        if (key->pubkey) {
            key->comp_pubkey[i] = (char *)key->pubkey + publen;
            publen += key->pubkeylen_cmp[i];
        } else {
            key->comp_pubkey[i] = NULL;
        }
    }

    return 1;
}

int oqsx_composite_key_gen(OQSX_KEY *key) {
    int ret = 0, i;
    EVP_PKEY *pkey = NULL;
    char *name;

    ret = oqsx_composite_key_set_composites(key);
    for (i = 0; i < key->numkeys; i++) {
        if ((name = get_cmpname(OBJ_sn2nid(key->tls_name), i)) == NULL) {
            ON_ERR_GOTO(ret, err_gen);
        }
        if (get_oqsname_fromtls(name) == 0) {
            pkey = oqsx_key_gen_evp_key_sig(key->oqsx_provider_ctx.oqsx_evp_ctx,
                                            key->comp_pubkey[i],
                                            key->comp_privkey[i], 0);
            OPENSSL_free(name);
            ON_ERR_GOTO(pkey == NULL, err_gen);
            key->classical_pkey = pkey;
        } else {
            ret = OQS_SIG_keypair(key->oqsx_provider_ctx.oqsx_qs_ctx.sig,
                                  key->comp_pubkey[i], key->comp_privkey[i]);
            OPENSSL_free(name);
            ON_ERR_GOTO(ret, err_gen);
        }
    }

err_gen:
    if (ret) {
        EVP_PKEY_free(pkey);
        key->classical_pkey = NULL;
    }
    return ret;
}

OQSX_KEY *oqsx_composite_key_new(OQSX_KEY *ret, char *tls_name, int primitive,
                                 int bit_security) {
    int ret2 = 0, i;
    OQSX_EVP_CTX *evp_ctx = NULL;

    ret->numkeys = 2;
    ret->privkeylen = 0;
    ret->pubkeylen = 0;
    ret->privkeylen_cmp = OPENSSL_malloc(ret->numkeys * sizeof(size_t));
    ret->pubkeylen_cmp = OPENSSL_malloc(ret->numkeys * sizeof(size_t));
    ret->comp_privkey = OPENSSL_malloc(ret->numkeys * sizeof(void *));
    ret->comp_pubkey = OPENSSL_malloc(ret->numkeys * sizeof(void *));

    for (i = 0; i < ret->numkeys; i++) {
        char *name;
        if ((name = get_cmpname(OBJ_sn2nid(tls_name), i)) == NULL) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
            goto err;
        }
        if (get_oqsname_fromtls(name) != 0) {
            ret->oqsx_provider_ctx.oqsx_qs_ctx.sig =
                OQS_SIG_new(get_oqsname_fromtls(name));
            if (!ret->oqsx_provider_ctx.oqsx_qs_ctx.sig) {
                fprintf(stderr,
                        "Could not create OQS signature "
                        "algorithm %s. "
                        "Enabled in "
                        "liboqs?A\n",
                        name);
                goto err;
            }
            ret->privkeylen_cmp[i] =
                ret->oqsx_provider_ctx.oqsx_qs_ctx.sig->length_secret_key;
            ret->pubkeylen_cmp[i] =
                ret->oqsx_provider_ctx.oqsx_qs_ctx.sig->length_public_key;
        } else {
            evp_ctx = OPENSSL_zalloc(sizeof(OQSX_EVP_CTX));
            ON_ERR_GOTO(!evp_ctx, err);

            ret2 = oqsx_hybsig_init(bit_security, evp_ctx, name);
            ON_ERR_GOTO(ret2 <= 0 || !evp_ctx->ctx, err);
            ret->oqsx_provider_ctx.oqsx_evp_ctx = evp_ctx;
            ret->privkeylen_cmp[i] = ret->oqsx_provider_ctx.oqsx_evp_ctx
                                         ->evp_info->length_private_key;
            ret->pubkeylen_cmp[i] = ret->oqsx_provider_ctx.oqsx_evp_ctx
                                        ->evp_info->length_public_key;
        }
        ret->privkeylen += ret->privkeylen_cmp[i];
        ret->pubkeylen += ret->pubkeylen_cmp[i];
        OPENSSL_free(name);
    }
    ret->keytype = primitive;

    return ret;
err:
    ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
#ifdef OQS_PROVIDER_NOATOMIC
    if (ret->lock)
        CRYPTO_THREAD_lock_free(ret->lock);
#endif

    OPENSSL_free(ret->tls_name);
    OPENSSL_free(ret->propq);
    OPENSSL_free(ret->comp_privkey);
    OPENSSL_free(ret->comp_pubkey);
    OPENSSL_free(ret);
    return NULL;
}

const unsigned char *oqsx_composite_key_from_pkcs8(const unsigned char *p,
                                                   const X509_ALGOR *palg,
                                                   int *plenin,
                                                   int *comp_diff) {
    OQSX_KEY *oqsx = NULL;
    STACK_OF(ASN1_TYPE) *sk = NULL;
    ASN1_TYPE *aType = NULL;
    unsigned char *concat_key;
    const unsigned char *buf;
    int count, aux, i, j, buflen, key_diff = 0, keytype, nid, plen = *plenin;
    PKCS8_PRIV_KEY_INFO *p8inf_internal = NULL;
    const X509_ALGOR *palg_internal;
    OQSX_EVP_INFO nids_sig;
    const int max_nids_sigs = get_nids_sig_OSSL_NELEM();

    sk = d2i_ASN1_SEQUENCE_ANY(NULL, &p, plen);
    if (sk == NULL) {
        sk_ASN1_TYPE_pop_free(sk, &ASN1_TYPE_free);
        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
        return NULL;
    } else {
        count = sk_ASN1_TYPE_num(sk);
        plen = 2 * plen; // get more than necessary in case its needed
        concat_key = OPENSSL_zalloc(plen);

        aux = 0;
        for (i = 0; i < count; i++) {
            aType = sk_ASN1_TYPE_pop(sk); // this remove in FILO order, but we
                                          // need this in the opposite order
            p8inf_internal = PKCS8_PRIV_KEY_INFO_new();
            nid = 0;
            char *name;
            if ((name = get_cmpname(OBJ_obj2nid(palg->algorithm),
                                    count - 1 - i)) == NULL) {
                ASN1_TYPE_free(aType);
                OPENSSL_clear_free(concat_key, plen);
                PKCS8_PRIV_KEY_INFO_free(p8inf_internal);
                sk_ASN1_TYPE_free(sk);
                ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                return NULL;
            }
            buflen = aType->value.sequence->length;
            const unsigned char *buf2 = aType->value.sequence->data;

            p8inf_internal =
                d2i_PKCS8_PRIV_KEY_INFO(&p8inf_internal, &buf2, buflen);
            if (!PKCS8_pkey_get0(NULL, &buf, &buflen, &palg_internal,
                                 p8inf_internal)) {
                OPENSSL_free(name);
                ASN1_TYPE_free(aType);
                PKCS8_PRIV_KEY_INFO_free(p8inf_internal);
                OPENSSL_clear_free(concat_key, plen);
                sk_ASN1_TYPE_free(sk);
                return NULL;
            }

            keytype = OBJ_obj2nid(palg_internal->algorithm);

            // Checking OPTIONAL params on EC
            if (keytype == EVP_PKEY_EC) {
                nid = OBJ_obj2nid(palg_internal->parameter->value.object);
                for (j = 0; j < max_nids_sigs; j++) {
                    nids_sig = get_nids_sig(j);
                    if ((nids_sig.nid == nid) &&
                        (nids_sig.length_private_key >
                         buflen)) { // check if the curve is the
                                    // same and if the key len is
                                    // smaller than the max key
                                    // size
                        EVP_PKEY *ec_pkey;
                        OSSL_PARAM params[3];
                        int include_pub = 1;
                        const unsigned char *buf3 = aType->value.sequence->data;
                        unsigned char *buf4, *buf5;

                        if (buflen != nids_sig.kex_length_secret +
                                          7) { // no OPTIONAL
                                               // ECParameter and no
                                               // OPTIONAL Pubkey
                            OPENSSL_free(name);
                            ASN1_TYPE_free(aType);
                            PKCS8_PRIV_KEY_INFO_free(p8inf_internal);
                            OPENSSL_clear_free(concat_key, plen);
                            sk_ASN1_TYPE_free(sk);
                            return NULL;
                        }
                        ec_pkey = EVP_PKEY_new();
                        d2i_PrivateKey(
                            EVP_PKEY_EC, &ec_pkey, &buf3,
                            aType->value.sequence->length); // create
                                                            // a new
                                                            // EVP_PKEY
                                                            // using
                                                            // ec
                                                            // priv
                                                            // key

                        // set parameters for the
                        // new priv key format
                        params[0] = OSSL_PARAM_construct_int(
                            OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC,
                            &include_pub); // add
                                           // pubkey
                                           // to
                                           // priv
                                           // key
                        params[1] = OSSL_PARAM_construct_utf8_string(
                            OSSL_PKEY_PARAM_EC_ENCODING,
                            OSSL_PKEY_EC_ENCODING_GROUP,
                            0); // add ECParam to
                                // the priv key
                        params[2] = OSSL_PARAM_construct_end();
                        EVP_PKEY_set_params(ec_pkey, params);

                        buf4 = OPENSSL_malloc(nids_sig.length_private_key);
                        buf5 = buf4;
                        buflen = i2d_PrivateKey(ec_pkey,
                                                &buf5); // encode priv
                                                        // key
                                                        // including
                                                        // parameters

                        aux += buflen;
                        memcpy(concat_key + plen - 1 - aux, buf4,
                               buflen); // fill
                                        // concat_key
                                        // starting at
                                        // the end

                        EVP_PKEY_free(ec_pkey);
                        OPENSSL_clear_free(buf4, buflen);
                        break;
                    }
                }
                if (j == max_nids_sigs)
                    nid = 0; // buflen is already with the
                             // correct size, changing nid
                             // to memcpy at the end
            }

            // if is a RSA key the actual encoding size might
            // be different from max size we calculate that
            // difference for to facilitate the key
            // reconstruction
            if (keytype == EVP_PKEY_RSA) {
                if (name[3] == '3') { // 3072
                    nids_sig = get_nids_sig(5);
                    key_diff = nids_sig.length_private_key - buflen;
                } else { // 2048
                    nids_sig = get_nids_sig(6);
                    key_diff = nids_sig.length_private_key - buflen;
                }
            }

            // removing extra OTECT STRING from ED25519 and ED448 keys
            if ((keytype == EVP_PKEY_ED25519) || (keytype == EVP_PKEY_ED448)) {
                ASN1_OCTET_STRING *ed_octet = NULL;
                ed_octet = d2i_ASN1_OCTET_STRING(&ed_octet, &buf, buflen);
                aux += ed_octet->length;
                memcpy(concat_key + plen - 1 - aux, ed_octet->data,
                       ed_octet->length);
                nid = 1; // setting to non zero value so the key is not
                         // copied again
                ASN1_OCTET_STRING_free(ed_octet);
            }

            if (!nid) {
                aux += buflen;
                memcpy(concat_key + plen - 1 - aux, buf,
                       buflen); // fill concat_key
                                // starting at the end
            }

            OPENSSL_free(name);
            PKCS8_PRIV_KEY_INFO_free(p8inf_internal);
            ASN1_TYPE_free(aType);
        }

        p = OPENSSL_memdup(concat_key + plen - 1 - aux, aux);
        OPENSSL_clear_free(concat_key, plen);
        *plenin = aux; // update plen to correct size
        *comp_diff = key_diff;
        sk_ASN1_TYPE_free(sk);
    }

    return p;
}

const unsigned char *oqsx_composite_key_from_x509pubkey(const unsigned char *p,
                                                        int *plenin) {
    STACK_OF(ASN1_TYPE) *sk = NULL;
    ASN1_TYPE *aType = NULL;
    ASN1_OCTET_STRING *oct = NULL;
    const unsigned char *buf;
    unsigned char *concat_key;
    int count, aux, i, buflen, plen = *plenin;
    OQSX_KEY *oqsx = NULL;

    sk = d2i_ASN1_SEQUENCE_ANY(NULL, &p, plen);
    if (sk == NULL) {
        sk_ASN1_TYPE_pop_free(sk, &ASN1_TYPE_free);
        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
        return NULL;
    } else {
        count = sk_ASN1_TYPE_num(sk);
        concat_key = OPENSSL_zalloc(plen); // concat_key is allocated with plen,
                                           // which is the max value for pubkey

        aux = 0;
        for (i = 0; i < count; i++) {
            aType = sk_ASN1_TYPE_pop(sk); // this remove in FILO order, but we
                                          // need this in the opposite order
            buf = aType->value.sequence->data;
            buflen = aType->value.sequence->length;
            aux += buflen;
            memcpy(concat_key + plen - 1 - aux, buf,
                   buflen); // fill concat_key starting at the end
            ASN1_TYPE_free(aType);
        }

        p = OPENSSL_memdup(concat_key + plen - 1 - aux,
                           aux); // copy used memory on concat_key to p
        OPENSSL_clear_free(concat_key, plen);
        *plenin = aux; // update plen value
        sk_ASN1_TYPE_free(sk);
    }

    return p;
}

int oqsx_composite_key_maxsize(OQSX_KEY *key) {
    return sizeof(CompositeSignature) +
           key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info->length_signature +
           key->oqsx_provider_ctx.oqsx_qs_ctx.sig->length_signature;
}

void oqsx_composite_key_free(OQSX_KEY *key) {
    OPENSSL_free(key->privkeylen_cmp);
    OPENSSL_free(key->pubkeylen_cmp);
}
