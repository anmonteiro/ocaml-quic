(*----------------------------------------------------------------------------
 *  Copyright (c) 2020 António Nuno Monteiro
 *
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice,
 *  this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright
 *  notice, this list of conditions and the following disclaimer in the
 *  documentation and/or other materials provided with the distribution.
 *
 *  3. Neither the name of the copyright holder nor the names of its
 *  contributors may be used to endorse or promote products derived from this
 *  software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *---------------------------------------------------------------------------*)

module Mode = struct
  type t =
    | Client
    | Server

  let peer = function Client -> Server | Server -> Client
end

(* initial_salt: 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a *)
let initial_salt =
  Cstruct.of_string
    "\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17\x9a\xe6\xa4\xc8\x0c\xad\xcc\xbb\x7f\x0a"

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
      Cstruct.set_uint8 l 0 (Cstruct.length lbl);
      Cstruct.append l lbl
    and context =
      let l = Cstruct.create 1 in
      Cstruct.set_uint8 l 0 (Cstruct.length context);
      Cstruct.append l context
    in
    let lbl = Cstruct.concat [ len; label; context ] in
    lbl

  (* TODO: this is called `derive_secret_no_hash` in ocaml-tls, we should use
   * that. *)
  let expand_label ~hash ~prk ?length label =
    let length =
      match length with
      | None -> Mirage_crypto.Hash.digest_size hash
      | Some x -> x
    in
    let info = expand_label label Cstruct.empty length in
    let key = Hkdf.expand ~hash ~prk ~info length in
    key
end

module Kdf = struct
  (* From RFC<QUIC-TLS-RFC>§5.1:
   *   The keys used for packet protection are computed from the TLS secrets
   *   using the KDF provided by TLS. In TLS 1.3, the HKDF-Expand-Label
   *   function described in Section 7.1 of [TLS13] is used, using the hash
   *   function from the negotiated cipher suite. *)
  let get_key_and_iv ~hash ~kn ~ivn secret =
    let key = Hkdf.expand_label ~hash ~prk:secret ~length:kn "quic key" in
    let iv = Hkdf.expand_label ~hash ~prk:secret ~length:ivn "quic iv" in
    key, iv

  let get_header_protection_key ~hash ~kn secret =
    Hkdf.expand_label ~hash ~prk:secret ~length:kn "quic hp"

  let get_ku ~hash ~kn secret =
    Hkdf.expand_label ~hash ~prk:secret ~length:kn "quic ku"
end

let[@inline] is_long header =
  match Packet.Header.Type.parse (Cstruct.get_uint8 header 0) with
  | Long -> true
  | Short -> false

let[@inline] packet_number_length header =
  (* From RFC<QUIC-RFC>§17.2:
   *   In packet types which contain a Packet Number field, the least
   *   significant two bits (those with a mask of 0x03) of byte 0 contain the
   *   length of the packet number, encoded as an unsigned, two-bit integer
   *   that is one less than the length of the packet number field in bytes.
   *   That is, the length of the packet number field is the value of this
   *   field, plus one. *)
  (Cstruct.get_uint8 header 0 land 0x03) + 1

(* From RFC<QUIC-RFC>§Appendix A:
 *
 *   DecodePacketNumber(largest_pn, truncated_pn, pn_nbits):
 *      expected_pn  = largest_pn + 1
 *      pn_win       = 1 << pn_nbits
 *      pn_hwin      = pn_win / 2
 *      pn_mask      = pn_win - 1
 *      // The incoming packet number should be greater than
 *      // expected_pn - pn_hwin and less than or equal to
 *      // expected_pn + pn_hwin
 *      //
 *      // This means we can't just strip the trailing bits from
 *      // expected_pn and add the truncated_pn because that might
 *      // yield a value outside the window.
 *      //
 *      // The following code calculates a candidate value and
 *      // makes sure it's within the packet number window.
 *      // Note the extra checks to prevent overflow and underflow.
 *      candidate_pn = (expected_pn & ~pn_mask) | truncated_pn
 *      if candidate_pn <= expected_pn - pn_hwin and
 *         candidate_pn < (1 << 62) - pn_win:
 *         return candidate_pn + pn_win
 *      if candidate_pn > expected_pn + pn_hwin and
 *         candidate_pn >= pn_win:
 *         return candidate_pn - pn_win
 *      return candidate_pn
 *)
let decode_packet_number ~largest_pn ~truncated_pn ~pn_nbits =
  let expected_pn = Int64.add largest_pn 1L in
  let pn_win = Int64.shift_left 1L pn_nbits in
  let pn_hwin = Int64.div pn_win 2L in
  let pn_mask = Int64.sub pn_win 1L in
  let candidate_pn =
    Int64.logor (Int64.logand expected_pn (Int64.lognot pn_mask)) truncated_pn
  in
  if Int64.compare candidate_pn (Int64.sub expected_pn pn_hwin) <= 0
     && Int64.compare candidate_pn (Int64.sub (Int64.shift_left 1L 62) pn_win)
        < 0
  then Int64.add candidate_pn pn_win
  else if Int64.compare candidate_pn (Int64.add expected_pn pn_hwin) > 0
          && Int64.compare candidate_pn pn_win >= 0
  then Int64.sub candidate_pn pn_win
  else candidate_pn

module AEAD = struct
  type 'k aead_state =
    { cipher : 'k Tls.State.aead_cipher
    ; key : 'k
    }

  type cipher_st = AEAD : 'k aead_state -> cipher_st

  type t =
    { conn_id_len : int
    ; cipher : cipher_st
    ; ciphersuite : Tls.Ciphersuite.aead_cipher
    ; hp_key : Cstruct.t
    ; iv : Cstruct.t
    }

  let tag_len t =
    let (AEAD { cipher; _ }) = t.cipher in
    Tls.Crypto.tag_len cipher

  let encrypt_payload t ~packet_number ~header data =
    let { cipher = AEAD { cipher; key }; iv; _ } = t in
    (* From RFC<QUIC-TLS-RFC>§5.3:
     *   The nonce, N, is formed by combining the packet protection IV with the
     *   packet number. The 62 bits of the reconstructed QUIC packet number in
     *   network byte order are left-padded with zeros to the size of the IV.
     *   The exclusive OR of the padded packet number and the IV forms the AEAD
     *   nonce. *)
    let nonce = Tls.Crypto.aead_nonce iv packet_number in
    Tls.Crypto.encrypt_aead
      ~cipher
      ~key
      ~nonce
        (*
         * The associated data, A, for the AEAD is the contents of the QUIC
         * header, starting from the flags byte in either the short or long
         * header, up to and including the unprotected packet number. *)
      ~adata:header
      data

  let decrypt_payload t ~packet_number ~header ciphertext =
    let { cipher = AEAD { cipher; key }; iv; _ } = t in
    (* From RFC<QUIC-TLS-RFC>§5.3:
     *   The nonce, N, is formed by combining the packet protection IV with the
     *   packet number. The 62 bits of the reconstructed QUIC packet number in
     *   network byte order are left-padded with zeros to the size of the IV.
     *   The exclusive OR of the padded packet number and the IV forms the AEAD
     *   nonce. *)
    let nonce = Tls.Crypto.aead_nonce iv packet_number in
    Tls.Crypto.decrypt_aead
      ~cipher
      ~key
      ~nonce
        (*
         * The associated data, A, for the AEAD is the contents of the QUIC
         * header, starting from the flags byte in either the short or long
         * header, up to and including the unprotected packet number. *)
      ~adata:header
      ciphertext

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
      if is_long header
      then (* Long header: 4 bits masked *)
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
    let pn_offset = Cstruct.length header - pn_length in
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

  let variable_length_integer header ~off =
    let rec inner r off rem =
      match rem with
      | 0 -> r
      | n ->
        let b = Cstruct.get_uint8 header off in
        inner ((r * 256) + b) (off + 1) (n - 1)
    in
    let parse_remaining r n = inner r (off + 1) n in
    let first_byte = Cstruct.get_uint8 header off in
    let encoding = first_byte lsr 6 in
    let b1 = first_byte land 0b00111111 in
    match encoding with
    | 0 -> 1, b1
    | 1 -> 2, parse_remaining b1 1
    | 2 -> 4, parse_remaining b1 3
    | _ ->
      assert (encoding = 3);
      8, parse_remaining b1 7

  let parse_long_header_offset header =
    (*
     * Note: Sizes below are in bytes
     *
     * Initial Packet {
     *   Header Form, Fixed Bit, Type, Res. Bits, Packet Number Length (1),
     *   Version (4),
     *   DCID Len (1),
     *   Destination Connection ID (0..20),
     *   SCID Len (1),
     *   Source Connection ID (0..20),
     *   Token Length (i),
     *   Token (..),
     *   Length (i),
     *   Packet Number (8..32),     # Protected
     *   Protected Payload (0..24), # Skipped Part
     *   Protected Payload (128),   # Sampled Part
     *   Protected Payload (..)     # Remainder
     * }
     *)
    let dest_cid_len = Cstruct.get_uint8 header 5 in
    let src_cid_len = Cstruct.get_uint8 header (6 + dest_cid_len) in
    let token_length =
      match Packet.parse_type (Cstruct.get_uint8 header 0) with
      | Initial ->
        let varint_len, token_len =
          variable_length_integer header ~off:(7 + src_cid_len + dest_cid_len)
        in
        varint_len + token_len
      | _ -> 0
    in
    let payload_varint_len, _payload_len =
      variable_length_integer
        header
        ~off:(7 + src_cid_len + dest_cid_len + token_length)
    in
    (*
     * sample_offset = 7 + len(destination_connection_id) +
     *                     len(source_connection_id) +
     *                     len(payload_length) + 4
     * if packet_type == Initial:
     *     sample_offset += len(token_length) +
     *                      len(token)
     *)
    7 + dest_cid_len + src_cid_len + payload_varint_len + token_length + 4

  let sample_offset ~conn_id_len header =
    if is_long header
    then parse_long_header_offset header
    else
      (*
       * sample_offset = 1 + len(connection_id) + 4
       *
       * sample = packet[sample_offset..sample_offset+sample_leng
       *)
      1 + conn_id_len + 4

  let decrypt_header ~conn_id_len ~mask header =
    (* From RFC<QUIC-TLS-RFC>§5.4.1:
     *   The output of this algorithm is a 5 byte mask which is applied to the
     *   protected header fields using exclusive OR. *)
    let mask = Cstruct.sub mask 0 5 in
    let masked_bits =
      if is_long header
      then (* Long header: 4 bits masked *)
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
    (* From RFC<QUIC-TLS-RFC>§5.4.1:
     *   Removing header protection only differs in the order in which the
     *   packet number length (pn_length) is determined. *)
    let pn_length = packet_number_length header in
    let pn_offset = sample_offset ~conn_id_len header - 4 in
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

  module AES_ECB = Mirage_crypto.Cipher_block.AES.ECB

  let encrypt_or_decrypt_header_ecb t f ~sample header =
    (* From RFC<QUIC-TLS-RFC>§5.4.3:
     *   mask = AES-ECB(hp_key, sample) *)
    let mask = AES_ECB.encrypt ~key:(AES_ECB.of_secret t.hp_key) sample in
    f ~mask header

  let encrypt_or_decrypt_header_chacha20 t f ~sample header =
    let module Chacha20 = Mirage_crypto.Chacha20 in
    (* From RFC<QUIC-TLS-RFC>§5.4.3:
     *   counter = sample[0..3]
     *   nonce = sample[4..15]
     *   mask = ChaCha20(hp_key, counter, nonce, {0,0,0,0,0}) *)
    let counter = Cstruct.sub sample 0 4 in
    let nonce = Cstruct.sub sample 4 12 in
    let ctr =
      Int64.logand
        (Int64.of_int32 (Cstruct.LE.get_uint32 counter 0))
        0x00000000FFFFFFFFL
    in
    let mask =
      Chacha20.crypt
        ~key:(Chacha20.of_secret t.hp_key)
        ~nonce
        ~ctr
        (Cstruct.create 5)
    in
    f ~mask header

  let encrypt_or_decrypt_header t f =
    match t.ciphersuite with
    | Tls.Ciphersuite.AES_128_GCM | AES_256_GCM | AES_128_CCM | AES_256_CCM ->
      encrypt_or_decrypt_header_ecb t f
    | CHACHA20_POLY1305 -> encrypt_or_decrypt_header_chacha20 t f

  let encrypt_header t = encrypt_or_decrypt_header t encrypt_header

  let decrypt_header t =
    encrypt_or_decrypt_header t (decrypt_header ~conn_id_len:t.conn_id_len)

  let encrypt_packet t ~packet_number ~header data =
    let sealed_payload = encrypt_payload t ~packet_number ~header data in
    let offset =
      (* From RFC<QUIC-TLS-RFC>§5.4.2:
       *  This results in needing at least 3 bytes of frames in the unprotected
       *  payload if the packet number is encoded on a single byte, or 2 bytes
       *  of frames for a 2-byte packet number encoding. *)
      4 - packet_number_length header
    in
    let sample = Cstruct.sub sealed_payload offset 16 in
    let header = encrypt_header t ~sample header in
    Cstruct.append header sealed_payload

  type ret =
    { packet_number : int64
    ; header : Cstruct.t
    ; plaintext : Cstruct.t
    ; pn_length : int
    }

  (* Ciphertext includes header + payload *)
  let decrypt_packet t ~payload_length ~largest_pn ciphertext =
    let offset = sample_offset ~conn_id_len:t.conn_id_len ciphertext in
    let sample = Cstruct.sub ciphertext offset 16 in
    let header = decrypt_header t ~sample ciphertext in
    let pn_length = packet_number_length header in
    let off = offset - 4 in
    let truncated_pn =
      match pn_length with
      | 4 ->
        Int64.logand
          (Int64.of_int32 (Cstruct.BE.get_uint32 header off))
          0x00000000FFFFFFFFL
      | 3 ->
        Int64.of_int
          ((Cstruct.get_uint8 header off * (1 lsl 16))
          + Cstruct.BE.get_uint16 header (off + 1))
      | 2 -> Int64.of_int (Cstruct.BE.get_uint16 header off)
      | _ ->
        assert (pn_length = 1);
        Int64.of_int (Cstruct.get_uint8 header off)
    in
    let pn =
      decode_packet_number ~largest_pn ~pn_nbits:(8 * pn_length) ~truncated_pn
    in
    let header, ciphertext =
      ( Cstruct.sub ciphertext 0 (off + pn_length)
      , (* This cstruct can have coalesced packets. we just want to decrypt the
           ciphertext of `payload_length - packet_number_length`. *)
        Cstruct.sub ciphertext (off + pn_length) (payload_length - pn_length) )
    in

    match decrypt_payload t ~packet_number:pn ~header ciphertext with
    | Some plaintext ->
      Some { pn_length; packet_number = pn; header; plaintext }
    | None -> None

  let get_cipher_st : Tls.Ciphersuite.aead_cipher -> Cstruct.t -> cipher_st =
   fun ciphersuite secret ->
    match
      Tls.Crypto.Ciphers.get_aead ~secret ~nonce:Cstruct.empty ciphersuite
    with
    | Tls.State.AEAD { cipher; cipher_secret; _ } ->
      AEAD { cipher; key = cipher_secret }
    | CBC _ -> assert false

  let make ~ciphersuite secret =
    let ciphersuite13 = Tls.Ciphersuite.privprot13 ciphersuite in
    let hash = Tls.Ciphersuite.hash13 ciphersuite in
    let kn, ivn = Tls.Ciphersuite.kn_13 ciphersuite13 in
    let key, iv = Kdf.get_key_and_iv ~hash ~kn ~ivn secret in
    { conn_id_len = CID.src_length
    ; cipher = get_cipher_st ciphersuite13 key
    ; ciphersuite = ciphersuite13
    ; iv
    ; hp_key = Kdf.get_header_protection_key ~hash ~kn secret
    }
end

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
    | Mode.Client ->
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

  (* From RFC<QUIC-TLS-RFC>§5.2:
   *   The hash function for HKDF when deriving initial secrets and keys is
   *   SHA-256 [SHA].
   *
   * From RFC<QUIC-TLS-RFC>§5.3:
   *   Prior to establishing a shared secret, packets are protected with
   *   AEAD_AES_128_GCM and a key derived from the Destination Connection ID in
   *   the client's first Initial packet (see Section 5.2). *)
  let make ~mode dest_cid =
    let secret = get_secret ~mode (CID.to_string dest_cid) in
    AEAD.make ~ciphersuite:`AES_128_GCM_SHA256 secret
end

module Retry = struct
  module AES_GCM = Mirage_crypto.Cipher_block.AES.GCM

  (* From RFC<QUIC-TLS-RFC>§5.8:
   *   The secret key, K, is 128 bits equal to
   *   0xbe0c690b9f66575a1d766b54e368c84e.
   *
   *   The nonce, N, is 96 bits equal to 0x461599d35d632bf2239825bb.
   *
   *   The plaintext, P, is empty.
   *
   *   The associated data, A, is the contents of the Retry Pseudo-Packet [...].
   *)
  let key =
    AES_GCM.of_secret
      (Cstruct.of_string
         "\xbe\x0c\x69\x0b\x9f\x66\x57\x5a\x1d\x76\x6b\x54\xe3\x68\xc8\x4e")

  let nonce =
    Cstruct.of_string "\x46\x15\x99\xd3\x5d\x63\x2b\xf2\x23\x98\x25\xbb"

  let calculate_integrity_tag cid pseudo0 =
    let cid_len = CID.length cid in
    let cid = CID.to_string cid in
    let pseudo_len = cid_len + Bigstringaf.length pseudo0 + 1 in
    let pseudo = Cstruct.create pseudo_len in
    Cstruct.set_uint8 pseudo 0 cid_len;
    for i = 1 to cid_len do
      Cstruct.set_char pseudo i (String.unsafe_get cid (i - 1))
    done;
    for i = 0 to Bigstringaf.length pseudo0 - 1 do
      Cstruct.set_char
        pseudo
        (i + cid_len + 1)
        (Bigstringaf.unsafe_get pseudo0 i)
    done;
    AES_GCM.authenticate_encrypt ~key ~nonce ~adata:pseudo Cstruct.empty
end

type encdec =
  { encrypter : AEAD.t
  ; (* decrypter might not always be available at the same time as the
     * encrypter *)
    decrypter : AEAD.t option
  }
