type hash =
  | SHA256
  | SHA384

type cipher =
  | AES_128_GCM
  | AES_256_GCM
  | AES_128_CCM
  | AES_256_CCM
  | CHACHA20_POLY1305

type aead_ctx

external hkdf_extract : hash -> salt:string -> ikm:string -> string
  = "ocaml_quic_openssl_hkdf_extract"

external hkdf_expand :
  hash -> prk:string -> info:string -> length:int -> string
  = "ocaml_quic_openssl_hkdf_expand"

external aead_encrypt :
  cipher -> key:string -> nonce:string -> adata:string -> plaintext:string -> string
  = "ocaml_quic_openssl_aead_encrypt"

external aead_decrypt :
  cipher
  -> key:string
  -> nonce:string
  -> adata:string
  -> ciphertext:string
  -> string option
  = "ocaml_quic_openssl_aead_decrypt"

external aead_encrypt_ctx : cipher -> key:string -> nonce_len:int -> aead_ctx
  = "ocaml_quic_openssl_aead_encrypt_ctx"

external aead_decrypt_ctx : cipher -> key:string -> nonce_len:int -> aead_ctx
  = "ocaml_quic_openssl_aead_decrypt_ctx"

external aead_encrypt_with_ctx :
  aead_ctx -> nonce:string -> adata:string -> plaintext:string -> string
  = "ocaml_quic_openssl_aead_encrypt_with_ctx"

external aead_decrypt_with_ctx :
  aead_ctx -> nonce:string -> adata:string -> ciphertext:string -> string option
  = "ocaml_quic_openssl_aead_decrypt_with_ctx"

external aead_encrypt_with_ctx_pn :
  aead_ctx -> iv:string -> packet_number:int64 -> adata:string -> plaintext:string -> string
  = "ocaml_quic_openssl_aead_encrypt_with_ctx_pn"

external aead_decrypt_with_ctx_pn :
  aead_ctx -> iv:string -> packet_number:int64 -> adata:string -> ciphertext:string -> string option
  = "ocaml_quic_openssl_aead_decrypt_with_ctx_pn"

external hp_mask_aes_ecb : key:string -> sample:string -> string
  = "ocaml_quic_openssl_hp_mask_aes_ecb"

external hp_encrypt_header_aes_ecb :
  key:string -> sample:string -> header:string -> bytes
  = "ocaml_quic_openssl_hp_encrypt_header_aes_ecb"

external hp_decrypt_header_aes_ecb :
  key:string -> sample:string -> pn_offset:int -> ciphertext:bytes -> bytes
  = "ocaml_quic_openssl_hp_decrypt_header_aes_ecb"

external hp_mask_chacha20 : key:string -> sample:string -> string
  = "ocaml_quic_openssl_hp_mask_chacha20"

external aes_128_gcm_auth_tag :
  key:string -> nonce:string -> adata:string -> string
  = "ocaml_quic_openssl_aes_128_gcm_auth_tag"
