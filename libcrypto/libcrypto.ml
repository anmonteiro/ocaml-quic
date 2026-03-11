type hash =
  | SHA256
  | SHA384

type cipher =
  | AES_128_GCM
  | AES_256_GCM
  | AES_128_CCM
  | AES_256_CCM
  | CHACHA20_POLY1305

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

external hp_mask_aes_ecb : key:string -> sample:string -> string
  = "ocaml_quic_openssl_hp_mask_aes_ecb"

external hp_mask_chacha20 : key:string -> sample:string -> string
  = "ocaml_quic_openssl_hp_mask_chacha20"

external aes_128_gcm_auth_tag :
  key:string -> nonce:string -> adata:string -> string
  = "ocaml_quic_openssl_aes_128_gcm_auth_tag"
