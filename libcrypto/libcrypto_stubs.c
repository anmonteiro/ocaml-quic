#include <stdio.h>
#include <string.h>

#define CAML_NAME_SPACE
#include <caml/alloc.h>
#include <caml/custom.h>
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

static void ocaml_quic_make_nonce(unsigned char *nonce, size_t nonce_len,
                                  value viv, value vpacket_number) {
  uint64_t packet_number = Int64_val(vpacket_number);
  size_t iv_len = caml_string_length(viv);
  size_t i;

  if (iv_len != nonce_len)
    caml_invalid_argument("OpenSSL_crypto.aead_nonce");

  memcpy(nonce, String_val(viv), nonce_len);
  for (i = 0; i < 8 && i < nonce_len; i++) {
    nonce[nonce_len - 1 - i] ^=
        (unsigned char)((packet_number >> (8 * i)) & 0xff);
  }
}

struct ocaml_quic_hp_aes_ctx {
  EVP_CIPHER_CTX *ctx;
};

struct ocaml_quic_aead_ctx {
  EVP_CIPHER_CTX *ctx;
  int tag_len;
  int encrypt;
};

static void ocaml_quic_hp_aes_ctx_finalize(value vctx) {
  struct ocaml_quic_hp_aes_ctx *ctx = Data_custom_val(vctx);
  if (ctx->ctx != NULL) {
    EVP_CIPHER_CTX_free(ctx->ctx);
    ctx->ctx = NULL;
  }
}

static void ocaml_quic_aead_ctx_finalize(value vctx) {
  struct ocaml_quic_aead_ctx *ctx = Data_custom_val(vctx);
  if (ctx->ctx != NULL) {
    EVP_CIPHER_CTX_free(ctx->ctx);
    ctx->ctx = NULL;
  }
}

static struct custom_operations ocaml_quic_hp_aes_ctx_ops = {
    "ocaml_quic.openssl_hp_aes_ctx", ocaml_quic_hp_aes_ctx_finalize,
    custom_compare_default,          custom_hash_default,
    custom_serialize_default,        custom_deserialize_default,
    custom_compare_ext_default};

static struct custom_operations ocaml_quic_aead_ctx_ops = {
    "ocaml_quic.openssl_aead_ctx", ocaml_quic_aead_ctx_finalize,
    custom_compare_default,        custom_hash_default,
    custom_serialize_default,      custom_deserialize_default,
    custom_compare_ext_default};

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

static const EVP_CIPHER *ocaml_quic_hp_aes_ecb_cipher(size_t key_len,
                                                      const char *prefix) {
  switch (key_len) {
  case 16:
    return EVP_aes_128_ecb();
  case 32:
    return EVP_aes_256_ecb();
  default:
    caml_invalid_argument(prefix);
  }
}

static void ocaml_quic_hp_encrypt_block_ctx(EVP_CIPHER_CTX *ctx,
                                            const unsigned char *sample,
                                            unsigned char block[16],
                                            const char *prefix) {
  int out_len = 0;
  int final_len = 0;

  if (EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, NULL) <= 0 ||
      EVP_EncryptUpdate(ctx, block, &out_len, sample, 16) <= 0 ||
      EVP_EncryptFinal_ex(ctx, block + out_len, &final_len) <= 0 ||
      out_len + final_len != 16) {
    ocaml_quic_fail_openssl(prefix);
  }
}

static void ocaml_quic_hp_encrypt_block_key(const unsigned char *key,
                                            size_t key_len,
                                            const unsigned char *sample,
                                            unsigned char block[16],
                                            const char *prefix) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

  if (ctx == NULL)
    ocaml_quic_fail_openssl(prefix);

  if (EVP_EncryptInit_ex(ctx, ocaml_quic_hp_aes_ecb_cipher(key_len, prefix), NULL,
                         key, NULL) <= 0 ||
      EVP_CIPHER_CTX_set_padding(ctx, 0) <= 0) {
    EVP_CIPHER_CTX_free(ctx);
    ocaml_quic_fail_openssl(prefix);
  }

  ocaml_quic_hp_encrypt_block_ctx(ctx, sample, block, prefix);
  EVP_CIPHER_CTX_free(ctx);
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

CAMLprim value ocaml_quic_openssl_aead_encrypt_ctx(value vcipher, value vkey,
                                                   value vnonce_len) {
  CAMLparam3(vcipher, vkey, vnonce_len);
  CAMLlocal1(vctx);
  struct ocaml_quic_aead_ctx *ctx;
  const EVP_CIPHER *cipher = ocaml_quic_cipher_evp(Int_val(vcipher));

  vctx = caml_alloc_custom(&ocaml_quic_aead_ctx_ops, sizeof(*ctx), 0, 1);
  ctx = Data_custom_val(vctx);
  ctx->ctx = EVP_CIPHER_CTX_new();
  ctx->tag_len = ocaml_quic_tag_len(Int_val(vcipher));
  ctx->encrypt = 1;

  if (ctx->ctx == NULL)
    caml_failwith("OpenSSL_crypto.aead_encrypt_ctx");
  if (EVP_EncryptInit_ex(ctx->ctx, cipher, NULL, NULL, NULL) <= 0)
    ocaml_quic_fail_openssl("OpenSSL_crypto.aead_encrypt_ctx");
  if (EVP_CIPHER_CTX_ctrl(ctx->ctx, EVP_CTRL_AEAD_SET_IVLEN,
                          Int_val(vnonce_len), NULL) <= 0)
    ocaml_quic_fail_openssl("OpenSSL_crypto.aead_encrypt_ctx");
  if (EVP_EncryptInit_ex(ctx->ctx, NULL, NULL,
                         (const unsigned char *)String_val(vkey), NULL) <= 0)
    ocaml_quic_fail_openssl("OpenSSL_crypto.aead_encrypt_ctx");

  CAMLreturn(vctx);
}

CAMLprim value ocaml_quic_openssl_aead_decrypt_ctx(value vcipher, value vkey,
                                                   value vnonce_len) {
  CAMLparam3(vcipher, vkey, vnonce_len);
  CAMLlocal1(vctx);
  struct ocaml_quic_aead_ctx *ctx;
  const EVP_CIPHER *cipher = ocaml_quic_cipher_evp(Int_val(vcipher));

  vctx = caml_alloc_custom(&ocaml_quic_aead_ctx_ops, sizeof(*ctx), 0, 1);
  ctx = Data_custom_val(vctx);
  ctx->ctx = EVP_CIPHER_CTX_new();
  ctx->tag_len = ocaml_quic_tag_len(Int_val(vcipher));
  ctx->encrypt = 0;

  if (ctx->ctx == NULL)
    caml_failwith("OpenSSL_crypto.aead_decrypt_ctx");
  if (EVP_DecryptInit_ex(ctx->ctx, cipher, NULL, NULL, NULL) <= 0)
    ocaml_quic_fail_openssl("OpenSSL_crypto.aead_decrypt_ctx");
  if (EVP_CIPHER_CTX_ctrl(ctx->ctx, EVP_CTRL_AEAD_SET_IVLEN,
                          Int_val(vnonce_len), NULL) <= 0)
    ocaml_quic_fail_openssl("OpenSSL_crypto.aead_decrypt_ctx");
  if (EVP_DecryptInit_ex(ctx->ctx, NULL, NULL,
                         (const unsigned char *)String_val(vkey), NULL) <= 0)
    ocaml_quic_fail_openssl("OpenSSL_crypto.aead_decrypt_ctx");

  CAMLreturn(vctx);
}

static value ocaml_quic_aead_encrypt_with_ctx_impl(value vctx,
                                                   const unsigned char *nonce,
                                                   value vadata,
                                                   value vplaintext) {
  CAMLparam3(vctx, vadata, vplaintext);
  CAMLlocal1(result);
  struct ocaml_quic_aead_ctx *ctx = Data_custom_val(vctx);
  const unsigned char *adata = (const unsigned char *)String_val(vadata);
  const unsigned char *plaintext = (const unsigned char *)String_val(vplaintext);
  int adata_len = caml_string_length(vadata);
  int plaintext_len = caml_string_length(vplaintext);
  int out_len = 0;
  int len = 0;

  if (!ctx->encrypt)
    caml_invalid_argument("OpenSSL_crypto.aead_encrypt_with_ctx");

  result = caml_alloc_string(plaintext_len + ctx->tag_len);

  if (EVP_EncryptInit_ex(ctx->ctx, NULL, NULL, NULL, nonce) <= 0)
    goto err;
  if (adata_len > 0 &&
      EVP_EncryptUpdate(ctx->ctx, NULL, &len, adata, adata_len) <= 0)
    goto err;
  if (plaintext_len > 0 &&
      EVP_EncryptUpdate(ctx->ctx, (unsigned char *)Bytes_val(result), &len,
                        plaintext, plaintext_len) <= 0)
    goto err;
  out_len = len;
  if (plaintext_len == 0) {
    if (EVP_EncryptFinal_ex(ctx->ctx, NULL, &len) <= 0)
      goto err;
  } else {
    if (EVP_EncryptFinal_ex(ctx->ctx, (unsigned char *)Bytes_val(result) + out_len,
                            &len) <= 0)
      goto err;
    out_len += len;
  }
  if (out_len != plaintext_len)
    goto err;
  if (EVP_CIPHER_CTX_ctrl(ctx->ctx, EVP_CTRL_AEAD_GET_TAG, ctx->tag_len,
                          (unsigned char *)Bytes_val(result) + plaintext_len) <=
      0)
    goto err;

  CAMLreturn(result);

err:
  ocaml_quic_fail_openssl("OpenSSL_crypto.aead_encrypt_with_ctx");
  CAMLreturn(Val_unit);
}

static value ocaml_quic_aead_decrypt_with_ctx_impl(value vctx,
                                                   const unsigned char *nonce,
                                                   value vadata,
                                                   value vciphertext) {
  CAMLparam3(vctx, vadata, vciphertext);
  CAMLlocal2(result, some);
  struct ocaml_quic_aead_ctx *ctx = Data_custom_val(vctx);
  const unsigned char *adata = (const unsigned char *)String_val(vadata);
  const unsigned char *ciphertext =
      (const unsigned char *)String_val(vciphertext);
  int adata_len = caml_string_length(vadata);
  int ciphertext_len = caml_string_length(vciphertext);
  int plaintext_len = ciphertext_len - ctx->tag_len;
  int out_len = 0;
  int len = 0;

  if (ctx->encrypt)
    caml_invalid_argument("OpenSSL_crypto.aead_decrypt_with_ctx");
  if (plaintext_len < 0)
    CAMLreturn(Val_int(0));

  result = caml_alloc_string(plaintext_len);

  if (EVP_DecryptInit_ex(ctx->ctx, NULL, NULL, NULL, nonce) <= 0)
    goto fail;
  if (adata_len > 0 &&
      EVP_DecryptUpdate(ctx->ctx, NULL, &len, adata, adata_len) <= 0)
    goto fail;
  if (plaintext_len > 0 &&
      EVP_DecryptUpdate(ctx->ctx, (unsigned char *)Bytes_val(result), &len,
                        ciphertext, plaintext_len) <= 0)
    goto fail;
  out_len = len;
  if (EVP_CIPHER_CTX_ctrl(ctx->ctx, EVP_CTRL_AEAD_SET_TAG, ctx->tag_len,
                          (void *)(ciphertext + plaintext_len)) <= 0)
    goto fail;
  if (EVP_DecryptFinal_ex(ctx->ctx, (unsigned char *)Bytes_val(result) + out_len,
                          &len) <= 0)
    goto fail;
  out_len += len;
  if (out_len != plaintext_len)
    goto fail;

  some = ocaml_quic_some(result);
  CAMLreturn(some);

fail:
  CAMLreturn(Val_int(0));
}

static value ocaml_quic_aead_decrypt_with_ctx_bytes_impl(
    value vctx, const unsigned char *nonce, value vsrc, value vadata_len,
    value vciphertext_off, value vciphertext_len) {
  CAMLparam4(vctx, vsrc, vadata_len, vciphertext_len);
  CAMLxparam1(vciphertext_off);
  CAMLlocal2(result, some);
  struct ocaml_quic_aead_ctx *ctx = Data_custom_val(vctx);
  int adata_len = Int_val(vadata_len);
  int ciphertext_off = Int_val(vciphertext_off);
  int ciphertext_len = Int_val(vciphertext_len);
  int plaintext_len = ciphertext_len - ctx->tag_len;
  int out_len = 0;
  int len = 0;
  mlsize_t src_len = caml_string_length(vsrc);
  const unsigned char *src;
  const unsigned char *adata;
  const unsigned char *ciphertext;

  if (!ctx->encrypt)
    ;
  else
    caml_invalid_argument("OpenSSL_crypto.aead_decrypt_with_ctx_pn_bytes");

  if (adata_len < 0 || ciphertext_off < 0 || ciphertext_len < 0 ||
      (uintnat)adata_len > src_len || (uintnat)ciphertext_off > src_len ||
      (uintnat)ciphertext_len > src_len - (uintnat)ciphertext_off)
    caml_invalid_argument("OpenSSL_crypto.aead_decrypt_with_ctx_pn_bytes");

  if (plaintext_len < 0)
    CAMLreturn(Val_int(0));

  result = caml_alloc_string(plaintext_len);
  ctx = Data_custom_val(vctx);
  src = (const unsigned char *)Bytes_val(vsrc);
  adata = src;
  ciphertext = src + ciphertext_off;

  if (EVP_DecryptInit_ex(ctx->ctx, NULL, NULL, NULL, nonce) <= 0)
    goto fail;
  if (adata_len > 0 &&
      EVP_DecryptUpdate(ctx->ctx, NULL, &len, adata, adata_len) <= 0)
    goto fail;
  if (plaintext_len > 0 &&
      EVP_DecryptUpdate(ctx->ctx, (unsigned char *)Bytes_val(result), &len,
                        ciphertext, plaintext_len) <= 0)
    goto fail;
  out_len = len;
  if (EVP_CIPHER_CTX_ctrl(ctx->ctx, EVP_CTRL_AEAD_SET_TAG, ctx->tag_len,
                          (void *)(ciphertext + plaintext_len)) <= 0)
    goto fail;
  if (EVP_DecryptFinal_ex(ctx->ctx, (unsigned char *)Bytes_val(result) + out_len,
                          &len) <= 0)
    goto fail;
  out_len += len;
  if (out_len != plaintext_len)
    goto fail;

  some = ocaml_quic_some(result);
  CAMLreturn(some);

fail:
  CAMLreturn(Val_int(0));
}

CAMLprim value ocaml_quic_openssl_aead_decrypt_with_ctx_pn_bytes(
    value vctx, value viv, value vpacket_number, value vsrc, value vadata_len,
    value vciphertext_off, value vciphertext_len) {
  CAMLparam5(vctx, viv, vpacket_number, vsrc, vadata_len);
  CAMLxparam2(vciphertext_off, vciphertext_len);
  size_t nonce_len = caml_string_length(viv);
  unsigned char nonce_buf[32];

  if (nonce_len > sizeof(nonce_buf))
    caml_invalid_argument("OpenSSL_crypto.aead_decrypt_with_ctx_pn_bytes");

  ocaml_quic_make_nonce(nonce_buf, nonce_len, viv, vpacket_number);
  CAMLreturn(ocaml_quic_aead_decrypt_with_ctx_bytes_impl(
      vctx, nonce_buf, vsrc, vadata_len, vciphertext_off, vciphertext_len));
}

CAMLprim value ocaml_quic_openssl_aead_decrypt_with_ctx_pn_bytes_bytecode(
    value *argv, int argn) {
  (void)argn;
  return ocaml_quic_openssl_aead_decrypt_with_ctx_pn_bytes(
      argv[0], argv[1], argv[2], argv[3], argv[4], argv[5], argv[6]);
}

CAMLprim value ocaml_quic_openssl_aead_encrypt_with_ctx(value vctx,
                                                        value vnonce,
                                                        value vadata,
                                                        value vplaintext) {
  return ocaml_quic_aead_encrypt_with_ctx_impl(
      vctx, (const unsigned char *)String_val(vnonce), vadata, vplaintext);
}

CAMLprim value ocaml_quic_openssl_aead_decrypt_with_ctx(value vctx,
                                                        value vnonce,
                                                        value vadata,
                                                        value vciphertext) {
  return ocaml_quic_aead_decrypt_with_ctx_impl(
      vctx, (const unsigned char *)String_val(vnonce), vadata, vciphertext);
}

CAMLprim value ocaml_quic_openssl_aead_encrypt_with_ctx_pn(value vctx,
                                                           value viv,
                                                           value vpacket_number,
                                                           value vadata,
                                                           value vplaintext) {
  CAMLparam5(vctx, viv, vpacket_number, vadata, vplaintext);
  size_t nonce_len = caml_string_length(viv);
  unsigned char nonce_buf[32];

  if (nonce_len > sizeof(nonce_buf))
    caml_invalid_argument("OpenSSL_crypto.aead_encrypt_with_ctx_pn");

  ocaml_quic_make_nonce(nonce_buf, nonce_len, viv, vpacket_number);
  CAMLreturn(
      ocaml_quic_aead_encrypt_with_ctx_impl(vctx, nonce_buf, vadata, vplaintext));
}

CAMLprim value ocaml_quic_openssl_aead_decrypt_with_ctx_pn(value vctx,
                                                           value viv,
                                                           value vpacket_number,
                                                           value vadata,
                                                           value vciphertext) {
  CAMLparam5(vctx, viv, vpacket_number, vadata, vciphertext);
  size_t nonce_len = caml_string_length(viv);
  unsigned char nonce_buf[32];

  if (nonce_len > sizeof(nonce_buf))
    caml_invalid_argument("OpenSSL_crypto.aead_decrypt_with_ctx_pn");

  ocaml_quic_make_nonce(nonce_buf, nonce_len, viv, vpacket_number);
  CAMLreturn(
      ocaml_quic_aead_decrypt_with_ctx_impl(vctx, nonce_buf, vadata, vciphertext));
}

CAMLprim value ocaml_quic_openssl_hp_aes_ctx(value vkey) {
  CAMLparam1(vkey);
  CAMLlocal1(vctx);
  struct ocaml_quic_hp_aes_ctx *ctx;
  const EVP_CIPHER *cipher;

  vctx = caml_alloc_custom(&ocaml_quic_hp_aes_ctx_ops, sizeof(*ctx), 0, 1);
  ctx = Data_custom_val(vctx);
  ctx->ctx = EVP_CIPHER_CTX_new();
  if (ctx->ctx == NULL)
    ocaml_quic_fail_openssl("OpenSSL_crypto.hp_aes_ctx");

  cipher = ocaml_quic_hp_aes_ecb_cipher(caml_string_length(vkey),
                                        "OpenSSL_crypto.hp_aes_ctx");
  if (EVP_EncryptInit_ex(ctx->ctx, cipher, NULL,
                         (const unsigned char *)String_val(vkey), NULL) <= 0 ||
      EVP_CIPHER_CTX_set_padding(ctx->ctx, 0) <= 0) {
    ocaml_quic_fail_openssl("OpenSSL_crypto.hp_aes_ctx");
  }

  CAMLreturn(vctx);
}

CAMLprim value ocaml_quic_openssl_hp_mask_aes_ecb_ctx(value vctx,
                                                      value vsample) {
  CAMLparam2(vctx, vsample);
  CAMLlocal1(result);
  struct ocaml_quic_hp_aes_ctx *ctx = Data_custom_val(vctx);
  unsigned char block[16];

  if (caml_string_length(vsample) != 16)
    caml_invalid_argument("OpenSSL_crypto.hp_mask_aes_ecb_ctx");

  ocaml_quic_hp_encrypt_block_ctx(
      ctx->ctx, (const unsigned char *)String_val(vsample), block,
      "OpenSSL_crypto.hp_mask_aes_ecb_ctx");
  result = caml_alloc_string(5);
  memcpy(Bytes_val(result), block, 5);
  CAMLreturn(result);
}

CAMLprim value ocaml_quic_openssl_hp_mask_aes_ecb(value vkey, value vsample) {
  CAMLparam2(vkey, vsample);
  CAMLlocal1(result);
  unsigned char block[16];

  if (caml_string_length(vsample) != 16) {
    caml_invalid_argument("OpenSSL_crypto.hp_mask_aes_ecb");
  }

  ocaml_quic_hp_encrypt_block_key(
      (const unsigned char *)String_val(vkey), caml_string_length(vkey),
      (const unsigned char *)String_val(vsample), block,
      "OpenSSL_crypto.hp_mask_aes_ecb");
  result = caml_alloc_string(5);
  memcpy(Bytes_val(result), block, 5);
  CAMLreturn(result);
}

CAMLprim value ocaml_quic_openssl_hp_encrypt_header_aes_ecb(value vkey,
                                                            value vsample,
                                                            value vheader) {
  CAMLparam3(vkey, vsample, vheader);
  CAMLlocal1(result);
  unsigned char block[16];
  mlsize_t header_len = caml_string_length(vheader);
  int first;
  int pn_length;
  int pn_offset;
  int masked_bits;
  int i;

  if (caml_string_length(vsample) != 16)
    caml_invalid_argument("OpenSSL_crypto.hp_encrypt_header_aes_ecb");

  ocaml_quic_hp_encrypt_block_key(
      (const unsigned char *)String_val(vkey), caml_string_length(vkey),
      (const unsigned char *)String_val(vsample), block,
      "OpenSSL_crypto.hp_encrypt_header_aes_ecb");
  result = caml_alloc_string(header_len);
  memcpy(Bytes_val(result), String_val(vheader), header_len);

  first = Bytes_val(result)[0];
  pn_length = (first & 0x03) + 1;
  pn_offset = (int)header_len - pn_length;
  masked_bits = (first & 0x80) ? 0x0f : 0x1f;
  Bytes_val(result)[0] = first ^ (block[0] & masked_bits);
  for (i = 0; i < pn_length; i++)
    Bytes_val(result)[pn_offset + i] ^= block[i + 1];

  CAMLreturn(result);
}

CAMLprim value ocaml_quic_openssl_hp_encrypt_header_aes_ecb_at(value vkey,
                                                               value vsample_src,
                                                               value vsample_off,
                                                               value vheader) {
  CAMLparam4(vkey, vsample_src, vsample_off, vheader);
  CAMLlocal1(result);
  unsigned char block[16];
  mlsize_t src_len = caml_string_length(vsample_src);
  long sample_off = Long_val(vsample_off);
  mlsize_t header_len = caml_string_length(vheader);
  int first;
  int pn_length;
  int pn_offset;
  int masked_bits;
  int i;

  if (sample_off < 0 || (uintnat)sample_off + 16 > src_len)
    caml_invalid_argument("OpenSSL_crypto.hp_encrypt_header_aes_ecb_at");

  ocaml_quic_hp_encrypt_block_key(
      (const unsigned char *)String_val(vkey), caml_string_length(vkey),
      (const unsigned char *)Bytes_val(vsample_src) + sample_off, block,
      "OpenSSL_crypto.hp_encrypt_header_aes_ecb_at");
  result = caml_alloc_string(header_len);
  memcpy(Bytes_val(result), String_val(vheader), header_len);

  first = Bytes_val(result)[0];
  pn_length = (first & 0x03) + 1;
  pn_offset = (int)header_len - pn_length;
  masked_bits = (first & 0x80) ? 0x0f : 0x1f;
  Bytes_val(result)[0] = first ^ (block[0] & masked_bits);
  for (i = 0; i < pn_length; i++)
    Bytes_val(result)[pn_offset + i] ^= block[i + 1];

  CAMLreturn(result);
}

CAMLprim value ocaml_quic_openssl_hp_encrypt_header_aes_ecb_ctx_at(value vctx,
                                                                   value vsample_src,
                                                                   value vsample_off,
                                                                   value vheader) {
  CAMLparam4(vctx, vsample_src, vsample_off, vheader);
  CAMLlocal1(result);
  struct ocaml_quic_hp_aes_ctx *ctx = Data_custom_val(vctx);
  unsigned char block[16];
  mlsize_t src_len = caml_string_length(vsample_src);
  long sample_off = Long_val(vsample_off);
  mlsize_t header_len = caml_string_length(vheader);
  int first;
  int pn_length;
  int pn_offset;
  int masked_bits;
  int i;

  if (sample_off < 0 || (uintnat)sample_off + 16 > src_len)
    caml_invalid_argument("OpenSSL_crypto.hp_encrypt_header_aes_ecb_ctx_at");

  ocaml_quic_hp_encrypt_block_ctx(
      ctx->ctx, (const unsigned char *)Bytes_val(vsample_src) + sample_off, block,
      "OpenSSL_crypto.hp_encrypt_header_aes_ecb_ctx_at");
  result = caml_alloc_string(header_len);
  memcpy(Bytes_val(result), String_val(vheader), header_len);

  first = Bytes_val(result)[0];
  pn_length = (first & 0x03) + 1;
  pn_offset = (int)header_len - pn_length;
  masked_bits = (first & 0x80) ? 0x0f : 0x1f;
  Bytes_val(result)[0] = first ^ (block[0] & masked_bits);
  for (i = 0; i < pn_length; i++)
    Bytes_val(result)[pn_offset + i] ^= block[i + 1];

  CAMLreturn(result);
}

CAMLprim value ocaml_quic_openssl_hp_decrypt_header_aes_ecb(value vkey,
                                                            value vsample,
                                                            value vpn_offset,
                                                            value vciphertext) {
  CAMLparam4(vkey, vsample, vpn_offset, vciphertext);
  unsigned char block[16];
  int first;
  int pn_length;
  int pn_offset = Int_val(vpn_offset);
  int masked_bits;
  int i;

  if (caml_string_length(vsample) != 16)
    caml_invalid_argument("OpenSSL_crypto.hp_decrypt_header_aes_ecb");

  ocaml_quic_hp_encrypt_block_key(
      (const unsigned char *)String_val(vkey), caml_string_length(vkey),
      (const unsigned char *)String_val(vsample), block,
      "OpenSSL_crypto.hp_decrypt_header_aes_ecb");
  first = Bytes_val(vciphertext)[0];
  masked_bits = (first & 0x80) ? 0x0f : 0x1f;
  Bytes_val(vciphertext)[0] = first ^ (block[0] & masked_bits);
  pn_length = (Bytes_val(vciphertext)[0] & 0x03) + 1;
  for (i = 0; i < pn_length; i++)
    Bytes_val(vciphertext)[pn_offset + i] ^= block[i + 1];

  CAMLreturn(vciphertext);
}

CAMLprim value ocaml_quic_openssl_hp_decrypt_header_aes_ecb_at(value vkey,
                                                               value vsample_src,
                                                               value vsample_off,
                                                               value vpn_offset,
                                                               value vciphertext) {
  CAMLparam5(vkey, vsample_src, vsample_off, vpn_offset, vciphertext);
  unsigned char block[16];
  mlsize_t src_len = caml_string_length(vsample_src);
  long sample_off = Long_val(vsample_off);
  int first;
  int pn_length;
  int pn_offset = Int_val(vpn_offset);
  int masked_bits;
  int i;

  if (sample_off < 0 || (uintnat)sample_off + 16 > src_len)
    caml_invalid_argument("OpenSSL_crypto.hp_decrypt_header_aes_ecb_at");

  ocaml_quic_hp_encrypt_block_key(
      (const unsigned char *)String_val(vkey), caml_string_length(vkey),
      (const unsigned char *)Bytes_val(vsample_src) + sample_off, block,
      "OpenSSL_crypto.hp_decrypt_header_aes_ecb_at");
  first = Bytes_val(vciphertext)[0];
  masked_bits = (first & 0x80) ? 0x0f : 0x1f;
  Bytes_val(vciphertext)[0] = first ^ (block[0] & masked_bits);
  pn_length = (Bytes_val(vciphertext)[0] & 0x03) + 1;
  for (i = 0; i < pn_length; i++)
    Bytes_val(vciphertext)[pn_offset + i] ^= block[i + 1];

  CAMLreturn(vciphertext);
}

CAMLprim value ocaml_quic_openssl_hp_decrypt_header_aes_ecb_ctx_at(value vctx,
                                                                   value vsample_src,
                                                                   value vsample_off,
                                                                   value vpn_offset,
                                                                   value vciphertext) {
  CAMLparam5(vctx, vsample_src, vsample_off, vpn_offset, vciphertext);
  struct ocaml_quic_hp_aes_ctx *ctx = Data_custom_val(vctx);
  unsigned char block[16];
  mlsize_t src_len = caml_string_length(vsample_src);
  long sample_off = Long_val(vsample_off);
  int first;
  int pn_length;
  int pn_offset = Int_val(vpn_offset);
  int masked_bits;
  int i;

  if (sample_off < 0 || (uintnat)sample_off + 16 > src_len)
    caml_invalid_argument("OpenSSL_crypto.hp_decrypt_header_aes_ecb_ctx_at");

  ocaml_quic_hp_encrypt_block_ctx(
      ctx->ctx, (const unsigned char *)Bytes_val(vsample_src) + sample_off, block,
      "OpenSSL_crypto.hp_decrypt_header_aes_ecb_ctx_at");
  first = Bytes_val(vciphertext)[0];
  masked_bits = (first & 0x80) ? 0x0f : 0x1f;
  Bytes_val(vciphertext)[0] = first ^ (block[0] & masked_bits);
  pn_length = (Bytes_val(vciphertext)[0] & 0x03) + 1;
  for (i = 0; i < pn_length; i++)
    Bytes_val(vciphertext)[pn_offset + i] ^= block[i + 1];

  CAMLreturn(vciphertext);
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
