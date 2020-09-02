(* let aead_aes_gcm_tls13 key fixed_nonce = assert (String.length fixed_nonce =
   16) *)

(* AES_128_GCM_SHA256 *)
(* Mirage_crypto.Cipher_block.AES.GCM.authenticate_encrypt *)
(* key:Mirage_crypto.Cipher_block.AES.GCM.key -> *)
(* nonce:Cstruct.t -> ?adata:Cstruct.t -> Cstruct.t -> Cstruct.t *)

(* aes, err := aes.NewCipher(key) *)
(* if err != nil { *)
(* panic(err) *)
(* } *)
(* aead, err := cipher.NewGCM(aes) *)
(* if err != nil { *)
(* panic(err) *)
(* } *)

(* ret := &xorNonceAEAD{aead: aead} *)
(* copy(ret.nonceMask[:], nonceMask) *)
(* return ret *)
