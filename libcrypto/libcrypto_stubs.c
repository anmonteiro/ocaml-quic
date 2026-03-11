#include <stdio.h>
#include <string.h>

#define CAML_NAME_SPACE
#include <caml/alloc.h>
#include <caml/fail.h>
#include <caml/memory.h>
#include <caml/mlvalues.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/kdf.h>

enum ocaml_quic_hash {
  OCAML_QUIC_SHA256 = 0,
  OCAML_QUIC_SHA384 = 1,
};

enum ocaml_quic_cipher {
  OCAML_QUIC_AES_128_GCM = 0,
  OCAML_QUIC_AES_256_GCM = 1,
  OCAML_QUIC_AES_128_CCM = 2,
  OCAML_QUIC_AES_256_CCM = 3,
  OCAML_QUIC_CHACHA20_POLY1305 = 4,
};

static const EVP_MD *ocaml_quic_hash_md(value vhash) {
  switch (Int_val(vhash)) {
  case OCAML_QUIC_SHA256:
    return EVP_sha256();
  case OCAML_QUIC_SHA384:
    return EVP_sha384();
  default:
    caml_invalid_argument("OpenSSL_crypto.hash");
  }
}

static const EVP_CIPHER *ocaml_quic_cipher_evp(int cipher) {
  switch (cipher) {
  case OCAML_QUIC_AES_128_GCM:
    return EVP_aes_128_gcm();
  case OCAML_QUIC_AES_256_GCM:
    return EVP_aes_256_gcm();
  case OCAML_QUIC_AES_128_CCM:
    return EVP_aes_128_ccm();
  case OCAML_QUIC_AES_256_CCM:
    return EVP_aes_256_ccm();
  case OCAML_QUIC_CHACHA20_POLY1305:
    return EVP_chacha20_poly1305();
  default:
    caml_invalid_argument("OpenSSL_crypto.cipher");
  }
}

static int ocaml_quic_tag_len(int cipher) {
  switch (cipher) {
  case OCAML_QUIC_AES_128_GCM:
  case OCAML_QUIC_AES_256_GCM:
  case OCAML_QUIC_AES_128_CCM:
  case OCAML_QUIC_AES_256_CCM:
  case OCAML_QUIC_CHACHA20_POLY1305:
    return 16;
  default:
    caml_invalid_argument("OpenSSL_crypto.cipher");
  }
}

static value ocaml_quic_some(value v) {
  CAMLparam1(v);
  CAMLlocal1(some);
  some = caml_alloc(1, 0);
  Store_field(some, 0, v);
  CAMLreturn(some);
}

static void ocaml_quic_fail_openssl(const char *prefix) {
  unsigned long err = ERR_get_error();
  const char *reason = err == 0 ? NULL : ERR_reason_error_string(err);
  char buffer[256];

  if (reason == NULL) {
    caml_failwith(prefix);
  }

  snprintf(buffer, sizeof(buffer), "%s: %s", prefix, reason);
  caml_failwith(buffer);
}

static value ocaml_quic_hkdf_extract_impl(value vhash, value vsalt,
                                          value vikm) {
  CAMLparam3(vhash, vsalt, vikm);
  CAMLlocal1(result);
  EVP_PKEY_CTX *ctx = NULL;
  const EVP_MD *md = ocaml_quic_hash_md(vhash);
  size_t out_len = (size_t)EVP_MD_get_size(md);
  unsigned char *out;
  int ok;

  result = caml_alloc_string(out_len);
  out = (unsigned char *)Bytes_val(result);

  ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
  if (ctx == NULL)
    caml_failwith("OpenSSL_crypto.hkdf_extract");

  ok = EVP_PKEY_derive_init(ctx) > 0 &&
       EVP_PKEY_CTX_set_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) > 0 &&
       EVP_PKEY_CTX_set_hkdf_md(ctx, md) > 0 &&
       EVP_PKEY_CTX_set1_hkdf_salt(ctx, (const unsigned char *)String_val(vsalt),
                                   caml_string_length(vsalt)) > 0 &&
       EVP_PKEY_CTX_set1_hkdf_key(ctx, (const unsigned char *)String_val(vikm),
                                  caml_string_length(vikm)) > 0 &&
       EVP_PKEY_derive(ctx, out, &out_len) > 0;

  EVP_PKEY_CTX_free(ctx);

  if (!ok)
    caml_failwith("OpenSSL_crypto.hkdf_extract");

  CAMLreturn(result);
}

static value ocaml_quic_hkdf_expand_impl(value vhash, value vprk, value vinfo,
                                         value vlength) {
  CAMLparam4(vhash, vprk, vinfo, vlength);
  CAMLlocal1(result);
  EVP_PKEY_CTX *ctx = NULL;
  size_t out_len = (size_t)Int_val(vlength);
  unsigned char *out;
  int ok;

  result = caml_alloc_string(out_len);
  out = (unsigned char *)Bytes_val(result);

  ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
  if (ctx == NULL)
    caml_failwith("OpenSSL_crypto.hkdf_expand");

  ok = EVP_PKEY_derive_init(ctx) > 0 &&
       EVP_PKEY_CTX_set_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) > 0 &&
       EVP_PKEY_CTX_set_hkdf_md(ctx, ocaml_quic_hash_md(vhash)) > 0 &&
       EVP_PKEY_CTX_set1_hkdf_key(ctx, (const unsigned char *)String_val(vprk),
                                  caml_string_length(vprk)) > 0 &&
       EVP_PKEY_CTX_add1_hkdf_info(ctx, (const unsigned char *)String_val(vinfo),
                                   caml_string_length(vinfo)) > 0 &&
       EVP_PKEY_derive(ctx, out, &out_len) > 0;

  EVP_PKEY_CTX_free(ctx);

  if (!ok)
    caml_failwith("OpenSSL_crypto.hkdf_expand");

  CAMLreturn(result);
}

CAMLprim value ocaml_quic_openssl_hkdf_extract(value vhash, value vsalt,
                                               value vikm) {
  return ocaml_quic_hkdf_extract_impl(vhash, vsalt, vikm);
}

CAMLprim value ocaml_quic_openssl_hkdf_expand(value vhash, value vprk,
                                              value vinfo, value vlength) {
  return ocaml_quic_hkdf_expand_impl(vhash, vprk, vinfo, vlength);
}

static value ocaml_quic_aead_encrypt_gcm_like(int cipher_id, value vkey,
                                              value vnonce, value vadata,
                                              value vplaintext) {
  CAMLparam4(vkey, vnonce, vadata, vplaintext);
  CAMLlocal1(result);
  const EVP_CIPHER *cipher = ocaml_quic_cipher_evp(cipher_id);
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  const unsigned char *key = (const unsigned char *)String_val(vkey);
  const unsigned char *nonce = (const unsigned char *)String_val(vnonce);
  const unsigned char *adata = (const unsigned char *)String_val(vadata);
  const unsigned char *plaintext = (const unsigned char *)String_val(vplaintext);
  int adata_len = caml_string_length(vadata);
  int plaintext_len = caml_string_length(vplaintext);
  int nonce_len = caml_string_length(vnonce);
  int out_len = 0;
  int len = 0;
  int tag_len = ocaml_quic_tag_len(cipher_id);

  if (ctx == NULL)
    caml_failwith("OpenSSL_crypto.aead_encrypt");

  result = caml_alloc_string(plaintext_len + tag_len);

  if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) <= 0)
    goto err;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, nonce_len, NULL) <= 0)
    goto err;
  if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) <= 0)
    goto err;
  if (adata_len > 0 &&
      EVP_EncryptUpdate(ctx, NULL, &len, adata, adata_len) <= 0)
    goto err;
  if (plaintext_len > 0 &&
      EVP_EncryptUpdate(ctx, (unsigned char *)Bytes_val(result), &len, plaintext,
                        plaintext_len) <= 0)
    goto err;
  out_len = len;
  if (plaintext_len == 0) {
    if (EVP_EncryptFinal_ex(ctx, NULL, &len) <= 0)
      goto err;
  } else {
    if (EVP_EncryptFinal_ex(ctx, (unsigned char *)Bytes_val(result) + out_len,
                            &len) <= 0)
      goto err;
    out_len += len;
  }
  if (out_len != plaintext_len)
    goto err;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_len,
                          (unsigned char *)Bytes_val(result) + plaintext_len) <=
      0)
    goto err;

  EVP_CIPHER_CTX_free(ctx);
  CAMLreturn(result);

err:
  EVP_CIPHER_CTX_free(ctx);
  ocaml_quic_fail_openssl("OpenSSL_crypto.aead_encrypt");
  CAMLreturn(Val_unit);
}

static value ocaml_quic_aead_encrypt_ccm(int cipher_id, value vkey,
                                         value vnonce, value vadata,
                                         value vplaintext) {
  CAMLparam4(vkey, vnonce, vadata, vplaintext);
  CAMLlocal1(result);
  const EVP_CIPHER *cipher = ocaml_quic_cipher_evp(cipher_id);
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  const unsigned char *key = (const unsigned char *)String_val(vkey);
  const unsigned char *nonce = (const unsigned char *)String_val(vnonce);
  const unsigned char *adata = (const unsigned char *)String_val(vadata);
  const unsigned char *plaintext = (const unsigned char *)String_val(vplaintext);
  int adata_len = caml_string_length(vadata);
  int plaintext_len = caml_string_length(vplaintext);
  int nonce_len = caml_string_length(vnonce);
  int out_len = 0;
  int len = 0;
  int tag_len = ocaml_quic_tag_len(cipher_id);

  if (ctx == NULL)
    caml_failwith("OpenSSL_crypto.aead_encrypt");

  result = caml_alloc_string(plaintext_len + tag_len);

  if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) <= 0)
    goto err;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, nonce_len, NULL) <= 0)
    goto err;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_len, NULL) <= 0)
    goto err;
  if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) <= 0)
    goto err;
  if (EVP_EncryptUpdate(ctx, NULL, &len, NULL, plaintext_len) <= 0)
    goto err;
  if (adata_len > 0 &&
      EVP_EncryptUpdate(ctx, NULL, &len, adata, adata_len) <= 0)
    goto err;
  if (plaintext_len > 0 &&
      EVP_EncryptUpdate(ctx, (unsigned char *)Bytes_val(result), &len, plaintext,
                        plaintext_len) <= 0)
    goto err;
  out_len = len;
  if (out_len != plaintext_len)
    goto err;
  if (EVP_EncryptFinal_ex(ctx, (unsigned char *)Bytes_val(result) + out_len,
                          &len) <= 0)
    goto err;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_len,
                          (unsigned char *)Bytes_val(result) + plaintext_len) <=
      0)
    goto err;

  EVP_CIPHER_CTX_free(ctx);
  CAMLreturn(result);

err:
  EVP_CIPHER_CTX_free(ctx);
  ocaml_quic_fail_openssl("OpenSSL_crypto.aead_encrypt");
  CAMLreturn(Val_unit);
}

CAMLprim value ocaml_quic_openssl_aead_encrypt(value vcipher, value vkey,
                                               value vnonce, value vadata,
                                               value vplaintext) {
  int cipher_id = Int_val(vcipher);

  switch (cipher_id) {
  case OCAML_QUIC_AES_128_CCM:
  case OCAML_QUIC_AES_256_CCM:
    return ocaml_quic_aead_encrypt_ccm(cipher_id, vkey, vnonce, vadata,
                                       vplaintext);
  default:
    return ocaml_quic_aead_encrypt_gcm_like(cipher_id, vkey, vnonce, vadata,
                                            vplaintext);
  }
}

static value ocaml_quic_aead_decrypt_gcm_like(int cipher_id, value vkey,
                                              value vnonce, value vadata,
                                              value vciphertext) {
  CAMLparam4(vkey, vnonce, vadata, vciphertext);
  CAMLlocal2(result, some);
  const EVP_CIPHER *cipher = ocaml_quic_cipher_evp(cipher_id);
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  const unsigned char *key = (const unsigned char *)String_val(vkey);
  const unsigned char *nonce = (const unsigned char *)String_val(vnonce);
  const unsigned char *adata = (const unsigned char *)String_val(vadata);
  const unsigned char *ciphertext =
      (const unsigned char *)String_val(vciphertext);
  int adata_len = caml_string_length(vadata);
  int ciphertext_len = caml_string_length(vciphertext);
  int nonce_len = caml_string_length(vnonce);
  int tag_len = ocaml_quic_tag_len(cipher_id);
  int plaintext_len = ciphertext_len - tag_len;
  int out_len = 0;
  int len = 0;

  if (ctx == NULL)
    caml_failwith("OpenSSL_crypto.aead_decrypt");
  if (plaintext_len < 0) {
    EVP_CIPHER_CTX_free(ctx);
    CAMLreturn(Val_int(0));
  }

  result = caml_alloc_string(plaintext_len);

  if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) <= 0)
    goto fail;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, nonce_len, NULL) <= 0)
    goto fail;
  if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) <= 0)
    goto fail;
  if (adata_len > 0 &&
      EVP_DecryptUpdate(ctx, NULL, &len, adata, adata_len) <= 0)
    goto fail;
  if (plaintext_len > 0 &&
      EVP_DecryptUpdate(ctx, (unsigned char *)Bytes_val(result), &len,
                        ciphertext, plaintext_len) <= 0)
    goto fail;
  out_len = len;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_len,
                          (void *)(ciphertext + plaintext_len)) <= 0)
    goto fail;
  if (EVP_DecryptFinal_ex(ctx, (unsigned char *)Bytes_val(result) + out_len,
                          &len) <= 0)
    goto fail;
  out_len += len;
  if (out_len != plaintext_len)
    goto fail;

  EVP_CIPHER_CTX_free(ctx);
  some = ocaml_quic_some(result);
  CAMLreturn(some);

fail:
  EVP_CIPHER_CTX_free(ctx);
  CAMLreturn(Val_int(0));
}

static value ocaml_quic_aead_decrypt_ccm(int cipher_id, value vkey,
                                         value vnonce, value vadata,
                                         value vciphertext) {
  CAMLparam4(vkey, vnonce, vadata, vciphertext);
  CAMLlocal2(result, some);
  const EVP_CIPHER *cipher = ocaml_quic_cipher_evp(cipher_id);
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  const unsigned char *key = (const unsigned char *)String_val(vkey);
  const unsigned char *nonce = (const unsigned char *)String_val(vnonce);
  const unsigned char *adata = (const unsigned char *)String_val(vadata);
  const unsigned char *ciphertext =
      (const unsigned char *)String_val(vciphertext);
  int adata_len = caml_string_length(vadata);
  int ciphertext_len = caml_string_length(vciphertext);
  int nonce_len = caml_string_length(vnonce);
  int tag_len = ocaml_quic_tag_len(cipher_id);
  int plaintext_len = ciphertext_len - tag_len;
  int len = 0;

  if (ctx == NULL)
    caml_failwith("OpenSSL_crypto.aead_decrypt");
  if (plaintext_len < 0) {
    EVP_CIPHER_CTX_free(ctx);
    CAMLreturn(Val_int(0));
  }

  result = caml_alloc_string(plaintext_len);

  if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) <= 0)
    goto fail;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, nonce_len, NULL) <= 0)
    goto fail;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_len,
                          (void *)(ciphertext + plaintext_len)) <= 0)
    goto fail;
  if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) <= 0)
    goto fail;
  if (EVP_DecryptUpdate(ctx, NULL, &len, NULL, plaintext_len) <= 0)
    goto fail;
  if (adata_len > 0 &&
      EVP_DecryptUpdate(ctx, NULL, &len, adata, adata_len) <= 0)
    goto fail;
  if (plaintext_len > 0 &&
      EVP_DecryptUpdate(ctx, (unsigned char *)Bytes_val(result), &len,
                        ciphertext, plaintext_len) <= 0)
    goto fail;
  if (len != plaintext_len)
    goto fail;

  EVP_CIPHER_CTX_free(ctx);
  some = ocaml_quic_some(result);
  CAMLreturn(some);

fail:
  EVP_CIPHER_CTX_free(ctx);
  CAMLreturn(Val_int(0));
}

CAMLprim value ocaml_quic_openssl_aead_decrypt(value vcipher, value vkey,
                                               value vnonce, value vadata,
                                               value vciphertext) {
  int cipher_id = Int_val(vcipher);

  switch (cipher_id) {
  case OCAML_QUIC_AES_128_CCM:
  case OCAML_QUIC_AES_256_CCM:
    return ocaml_quic_aead_decrypt_ccm(cipher_id, vkey, vnonce, vadata,
                                       vciphertext);
  default:
    return ocaml_quic_aead_decrypt_gcm_like(cipher_id, vkey, vnonce, vadata,
                                            vciphertext);
  }
}

CAMLprim value ocaml_quic_openssl_hp_mask_aes_ecb(value vkey, value vsample) {
  CAMLparam2(vkey, vsample);
  CAMLlocal1(result);
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  const EVP_CIPHER *cipher;
  int out_len = 0;
  int len = 0;

  if (ctx == NULL)
    caml_failwith("OpenSSL_crypto.hp_mask_aes_ecb");
  if (caml_string_length(vsample) != 16) {
    EVP_CIPHER_CTX_free(ctx);
    caml_invalid_argument("OpenSSL_crypto.hp_mask_aes_ecb");
  }

  switch (caml_string_length(vkey)) {
  case 16:
    cipher = EVP_aes_128_ecb();
    break;
  case 32:
    cipher = EVP_aes_256_ecb();
    break;
  default:
    EVP_CIPHER_CTX_free(ctx);
    caml_invalid_argument("OpenSSL_crypto.hp_mask_aes_ecb");
  }

  result = caml_alloc_string(16);
  if (EVP_EncryptInit_ex(ctx, cipher, NULL,
                         (const unsigned char *)String_val(vkey), NULL) <= 0)
    goto err;
  if (EVP_CIPHER_CTX_set_padding(ctx, 0) <= 0)
    goto err;
  if (EVP_EncryptUpdate(ctx, (unsigned char *)Bytes_val(result), &out_len,
                        (const unsigned char *)String_val(vsample), 16) <= 0)
    goto err;
  if (EVP_EncryptFinal_ex(ctx, (unsigned char *)Bytes_val(result) + out_len,
                          &len) <= 0)
    goto err;
  if (out_len + len != 16)
    goto err;

  EVP_CIPHER_CTX_free(ctx);
  CAMLreturn(result);

err:
  EVP_CIPHER_CTX_free(ctx);
  ocaml_quic_fail_openssl("OpenSSL_crypto.hp_mask_aes_ecb");
  CAMLreturn(Val_unit);
}

CAMLprim value ocaml_quic_openssl_hp_mask_chacha20(value vkey, value vsample) {
  CAMLparam2(vkey, vsample);
  CAMLlocal1(result);
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  unsigned char iv[16];
  unsigned char zeroes[5] = {0, 0, 0, 0, 0};
  int out_len = 0;
  int len = 0;
  int sample_len = caml_string_length(vsample);

  if (ctx == NULL)
    caml_failwith("OpenSSL_crypto.hp_mask_chacha20");
  if (caml_string_length(vkey) != 32 || sample_len != 16) {
    EVP_CIPHER_CTX_free(ctx);
    caml_invalid_argument("OpenSSL_crypto.hp_mask_chacha20");
  }

  memcpy(iv, String_val(vsample), 16);

  result = caml_alloc_string(5);

  if (EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL,
                         (const unsigned char *)String_val(vkey), iv) <= 0)
    goto err;
  if (EVP_EncryptUpdate(ctx, (unsigned char *)Bytes_val(result), &out_len,
                        zeroes, 5) <= 0)
    goto err;
  if (EVP_EncryptFinal_ex(ctx, (unsigned char *)Bytes_val(result) + out_len,
                          &len) <= 0)
    goto err;
  if (out_len + len != 5)
    goto err;

  EVP_CIPHER_CTX_free(ctx);
  CAMLreturn(result);

err:
  EVP_CIPHER_CTX_free(ctx);
  ocaml_quic_fail_openssl("OpenSSL_crypto.hp_mask_chacha20");
  CAMLreturn(Val_unit);
}

CAMLprim value ocaml_quic_openssl_aes_128_gcm_auth_tag(value vkey, value vnonce,
                                                       value vadata) {
  CAMLparam3(vkey, vnonce, vadata);
  CAMLlocal1(result);
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int nonce_len = caml_string_length(vnonce);
  int adata_len = caml_string_length(vadata);
  int len = 0;

  if (ctx == NULL)
    caml_failwith("OpenSSL_crypto.aes_128_gcm_auth_tag");
  if (caml_string_length(vkey) != 16) {
    EVP_CIPHER_CTX_free(ctx);
    caml_invalid_argument("OpenSSL_crypto.aes_128_gcm_auth_tag");
  }

  result = caml_alloc_string(16);

  if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) <= 0)
    goto err;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, nonce_len, NULL) <= 0)
    goto err;
  if (EVP_EncryptInit_ex(ctx, NULL, NULL,
                         (const unsigned char *)String_val(vkey),
                         (const unsigned char *)String_val(vnonce)) <= 0)
    goto err;
  if (adata_len > 0 &&
      EVP_EncryptUpdate(ctx, NULL, &len,
                        (const unsigned char *)String_val(vadata),
                        adata_len) <= 0)
    goto err;
  if (EVP_EncryptFinal_ex(ctx, NULL, &len) <= 0)
    goto err;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16,
                          (unsigned char *)Bytes_val(result)) <= 0)
    goto err;

  EVP_CIPHER_CTX_free(ctx);
  CAMLreturn(result);

err:
  EVP_CIPHER_CTX_free(ctx);
  ocaml_quic_fail_openssl("OpenSSL_crypto.aes_128_gcm_auth_tag");
  CAMLreturn(Val_unit);
}
