type mode =
  | Client
  | Server

(* initial_salt = 0xafbfec289993d24c9e9786f19c6111e04390a899 *)
let initial_salt =
  Cstruct.of_string
    "\xaf\xbf\xec\x28\x99\x93\xd2\x4c\x9e\x97\x86\xf1\x9c\x61\x11\xe0\x43\x90\xa8\x99"

module Hkdf = struct
  include Hkdf

  let expand_label label context length =
    let len =
      let b = Cstruct.create 2 in
      Cstruct.BE.set_uint16 b 0 length;
      b
    and label =
      let lbl = Cstruct.of_string ("tls13 " ^ label) in
      let l = Cstruct.create 1 in
      Cstruct.set_uint8 l 0 (Cstruct.len lbl);
      Cstruct.append l lbl
    and context =
      let l = Cstruct.create 1 in
      Cstruct.set_uint8 l 0 (Cstruct.len context);
      Cstruct.append l context
    in
    let lbl = Cstruct.concat [ len; label; context ] in
    lbl

  let expand_label ~hash ~prk ?length ?(ctx = Cstruct.empty) label =
    let length =
      match length with
      | None ->
        Mirage_crypto.Hash.digest_size hash
      | Some x ->
        x
    in
    let info = expand_label label ctx length in
    let key = Hkdf.expand ~hash ~prk ~info length in
    key
end

let[@inline] is_long header = Cstruct.get_uint8 header 0 land 0x80 = 0x80

let[@inline] packet_number_length header =
  (* From RFC<QUIC-RFC>§17.2:
   *   In packet types which contain a Packet Number field, the least
   *   significant two bits (those with a mask of 0x03) of byte 0 contain the
   *   length of the packet number, encoded as an unsigned, two-bit integer
   *   that is one less than the length of the packet number field in bytes.
   *   That is, the length of the packet number field is the value of this
   *   field, plus one. *)
  (Cstruct.get_uint8 header 0 land 0x03) + 1

module AEAD = struct
  (* Initial: AES_128_GCM_SHA256 *)
  type t =
    { encrypt_payload :
        packet_number:int64 -> header:Cstruct.t -> Cstruct.t -> Cstruct.t
    ; encrypt_header : sample:Cstruct.t -> Cstruct.t -> Cstruct.t
    }

  let encrypt_payload
      (type k)
      (module Cipher : Mirage_crypto.AEAD with type key = k)
      ~key
      ~iv
      ~packet_number
      ~header
      data
    =
    (* From RFC<QUIC-TLS-RFC>§5.3:
     *   The nonce, N, is formed by combining the packet protection IV with the
     *   packet number. The 62 bits of the reconstructed QUIC packet number in
     *   network byte order are left-padded with zeros to the size of the IV.
     *   The exclusive OR of the padded packet number and the IV forms the AEAD
     *   nonce. *)
    let nonce = Tls.Crypto.aead_nonce iv packet_number in
    Cipher.authenticate_encrypt
      ~key
      ~nonce
        (*
         * The associated data, A, for the AEAD is the contents of the QUIC
         * header, starting from the flags byte in either the short or long
         * header, up to and including the unprotected packet number. *)
      ~adata:header
      data

  type header_type =
    | Short
    | Long

  (* mutates [header] *)
  (*
   *  mask = header_protection(hp_key, sample)
   *
   *  pn_length = (packet[0] & 0x03) + 1
   *  if (packet[0] & 0x80) == 0x80:
   *     # Long header: 4 bits masked
   *     packet[0] ^= mask[0] & 0x0f
   *  else:
   *     # Short header: 5 bits masked
   *     packet[0] ^= mask[0] & 0x1f
   *
   *  # pn_offset is the start of the Packet Number field.
   *  packet[pn_offset:pn_offset+pn_length] ^= mask[1:1+pn_length]
   *)
  let encrypt_header ~mask header =
    let pn_length = packet_number_length header in
    (* From RFC<QUIC-TLS-RFC>§5.4.1:
     *   The output of this algorithm is a 5 byte mask which is applied to the
     *   protected header fields using exclusive OR. *)
    let mask = Cstruct.sub mask 0 5 in
    let masked_bits =
      if is_long header then (* Long header: 4 bits masked *)
        0x0f
      else (* Short header: 5 bits masked *)
        0x1f
    in
    (* From RFC<QUIC-TLS-RFC>§5.4.1:
     *   The least significant bits of the first byte of the packet are masked
     *   by the least significant bits of the first mask byte. *)
    let masked_header_first_byte =
      Cstruct.get_uint8 header 0 lxor (Cstruct.get_uint8 mask 0 land masked_bits)
    in
    Cstruct.set_uint8 header 0 masked_header_first_byte;
    let pn_offset = Cstruct.len header - pn_length in
    (* From RFC<QUIC-TLS-RFC>§5.4.1:
     *   [...] the packet number is masked with the remaining bytes. *)
    for i = 0 to pn_length - 1 do
      Cstruct.set_uint8
        header
        (pn_offset + i)
        (Cstruct.get_uint8 header (pn_offset + i)
        lxor Cstruct.get_uint8 mask (i + 1))
    done;
    header

  let encrypt_packet t ~packet_number ~header data =
    let sealed_payload = t.encrypt_payload ~packet_number ~header data in
    let offset =
      (* From RFC<QUIC-TLS-RFC>§5.4.2:
       *  This results in needing at least 3 bytes of frames in the unprotected
       *  payload if the packet number is encoded on a single byte, or 2 bytes
       *  of frames for a 2-byte packet number encoding. *)
      4 - packet_number_length header
    in
    let sample = Cstruct.sub sealed_payload offset 16 in
    let header = t.encrypt_header ~sample header in
    Cstruct.append header sealed_payload
end

let get_key_and_iv ~key_length secret =
  let key =
    Hkdf.expand_label ~hash:`SHA256 ~prk:secret ~length:key_length "quic key"
  in
  let iv = Hkdf.expand_label ~hash:`SHA256 ~prk:secret ~length:12 "quic iv" in
  key, iv

let get_header_protection_key ~length secret =
  Hkdf.expand_label ~hash:`SHA256 ~prk:secret ~length "quic hp"

let get_ku ~length secret =
  Hkdf.expand_label ~hash:`SHA256 ~prk:secret ~length "quic ku"

module InitialAEAD = struct
  let get_initial_secret dest_connection_id =
    (* From RFC<QUIC-TLS-RFC>§A.1:
     * initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id) *)
    Hkdf.extract
      ~hash:`SHA256
      ~salt:initial_salt
      (Cstruct.of_string dest_connection_id)

  let get_secret ~mode dest_connection_id =
    let initial_secret = get_initial_secret dest_connection_id in
    match mode with
    | Client ->
      (* From RFC<QUIC-TLS-RFC>§A.1:
       *
       *   client_initial_secret = HKDF-Expand-Label(initial_secret,
       *                                             "client in", "",
       *                                             Hash.length)
       *)
      Hkdf.expand_label
        ~hash:`SHA256
        ~prk:initial_secret
        ~length:Mirage_crypto.Hash.SHA256.digest_size
        "client in"
    | Server ->
      (* From RFC<QUIC-TLS-RFC>§A.1:
       *
       *   server_initial_secret = HKDF-Expand-Label(initial_secret,
       *                                             "server in", "",
       *                                             Hash.length)
       *)
      Hkdf.expand_label
        ~hash:`SHA256
        ~prk:initial_secret
        ~length:Mirage_crypto.Hash.SHA256.digest_size
        "server in"

  let get_key_and_iv secret = get_key_and_iv ~key_length:16 secret

  let get_header_protection_key secret =
    get_header_protection_key ~length:16 secret

  module AES_GCM = Mirage_crypto.Cipher_block.AES.GCM
  module AES_ECB = Mirage_crypto.Cipher_block.AES.ECB

  let make ~mode dest_cid =
    let secret = get_secret ~mode dest_cid in
    let key, iv = get_key_and_iv secret in
    { AEAD.encrypt_payload =
        AEAD.encrypt_payload (module AES_GCM) ~key:(AES_GCM.of_secret key) ~iv
    ; encrypt_header =
        (fun ~sample header ->
          let hp_key = get_header_protection_key secret in
          (* From RFC<QUIC-TLS-RFC>§5.4.3:
           *   mask = AES-ECB(hp_key, sample) *)
          let mask = AES_ECB.encrypt ~key:(AES_ECB.of_secret hp_key) sample in
          AEAD.encrypt_header ~mask header)
    }
end

module Retry = struct
  module AES_GCM = Mirage_crypto.Cipher_block.AES.GCM

  (* From RFC<QUIC-TLS-RFC>§5.8:
   *   The secret key, K, is 128 bits equal to
   *   0xccce187ed09a09d05728155a6cb96be1.
   *
   *   The nonce, N, is 96 bits equal to 0xe54930f97f2136f0530a8c1c.
   *
   *   The plaintext, P, is empty.
   *
   *   The associated data, A, is the contents of the Retry Pseudo-Packet [...].
   *)
  let key =
    AES_GCM.of_secret
      (Cstruct.of_string
         "\xcc\xce\x18\x7e\xd0\x9a\x09\xd0\x57\x28\x15\x5a\x6c\xb9\x6b\xe1")

  let nonce =
    Cstruct.of_string "\xe5\x49\x30\xf9\x7f\x21\x36\xf0\x53\x0a\x8c\x1c"

  let calculate_integrity_tag { Packet.CID.length; id } pseudo0 =
    let pseudo_len = length + Bigstringaf.length pseudo0 + 1 in
    let pseudo = Cstruct.create pseudo_len in
    Cstruct.set_uint8 pseudo 0 length;
    for i = 1 to length do
      Cstruct.set_char pseudo i (String.unsafe_get id (i - 1))
    done;
    for i = 0 to Bigstringaf.length pseudo0 - 1 do
      Cstruct.set_char
        pseudo
        (i + length + 1)
        (Bigstringaf.unsafe_get pseudo0 i)
    done;
    AES_GCM.authenticate_encrypt ~key ~nonce ~adata:pseudo Cstruct.empty
end

module ChaCha20 = struct
  let get_key_and_iv secret = get_key_and_iv ~key_length:32 secret

  let get_header_protection_key secret =
    get_header_protection_key ~length:32 secret

  let get_ku secret = get_ku ~length:32 secret

  module Chacha20 = Mirage_crypto.Chacha20

  let make ~secret =
    let key, iv = get_key_and_iv secret in
    { AEAD.encrypt_payload =
        AEAD.encrypt_payload (module Chacha20) ~key:(Chacha20.of_secret key) ~iv
    ; encrypt_header =
        (fun ~sample header ->
          (* From RFC<QUIC-TLS-RFC>§5.4.3:
           *   counter = sample[0..3]
           *   nonce = sample[4..15]
           *   mask = ChaCha20(hp_key, counter, nonce, {0,0,0,0,0}) *)
          let hp_key = get_header_protection_key secret in
          let counter = Cstruct.sub sample 0 4 in
          let nonce = Cstruct.sub sample 4 12 in
          let mask =
            Chacha20.crypt
              ~key:(Chacha20.of_secret hp_key)
              ~nonce
              ~ctr:(Int64.of_int32 (Cstruct.LE.get_uint32 counter 0))
              (Cstruct.create 5)
          in
          AEAD.encrypt_header ~mask header)
    }
end

module Encryption_level = struct
  (* From RFC<QUIC-TLS-RFC>§A.1:
   *   Data is protected using a number of encryption levels:
   *
   *   Initial Keys
   *   Early Data (0-RTT) Keys
   *   Handshake Keys
   *   Application Data (1-RTT) Keys
   *)
  type t =
    | Initial
    | Zero_RTT
    | Handshake
    | Application_Data
end
