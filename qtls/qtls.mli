module State : sig
  type encryption_level =
    | Initial
    | Zero_RTT
    | Handshake
    | Application_data

  type crypto_state = { traffic_secret : string }

  type rec_resp =
    [ `Change_enc of crypto_state
    | `Change_dec of crypto_state
    | `Record of Tls.Packet.content_type * string
    | `Level_change_enc of encryption_level * crypto_state
    | `Level_change_dec of encryption_level * crypto_state
    | `Level_record of encryption_level * string
    ]
end

type t
type failure

type handled =
  { tls_state : t
  ; tls_packets : State.rec_resp list
  ; was_handshake_in_progress : bool
  }

val server : certificates:Tls.Config.own_cert -> alpn_protocols:string list -> t

val client
  :  ?authenticator:X509.Authenticator.t
  -> alpn_protocols:string list
  -> host:string
  -> string
  -> t

val handle_raw_record
  :  ?embed_quic_transport_params:(string option -> string option)
  -> t
  -> string
  -> (handled, failure) result

val current_cipher : t -> Tls.Ciphersuite.ciphersuite13
val transport_params : t -> string option
val alpn_protocol : t -> string option
val handshake_in_progress : t -> bool
val initial_packets : t -> handled
val alert_of_failure : t -> failure -> int
