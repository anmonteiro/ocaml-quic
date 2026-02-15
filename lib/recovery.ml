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

type sent =
  { frames : Frame.t list
  ; packet_number : int64
  ; ack_eliciting : bool
  }

module Q : Psq.S with type k = int64 and type p = sent =
  Psq.Make
    (Int64)
    (struct
      type t = sent

      let compare { packet_number = pn1; _ } { packet_number = pn2; _ } =
        compare pn1 pn2
    end)

type info =
  { mutable sent : Q.t
  ; acked : Frame.t Queue.t
  }

type t = info Spaces.t

let create () =
  let new_info () = { sent = Q.empty; acked = Queue.create () } in
  Spaces.create
    ~initial:(new_info ())
    ~handshake:(new_info ())
    ~application_data:(new_info ())

let on_packet_sent t ~encryption_level ~packet_number frames =
  let info = Spaces.of_encryption_level t encryption_level in
  let sent =
    { packet_number; frames; ack_eliciting = Frame.is_any_ack_eliciting frames }
  in
  assert (not (Q.mem packet_number info.sent));
  let sent' = Q.add packet_number sent info.sent in
  info.sent <- sent'

let on_ack_received t ~encryption_level ~ranges =
  let info = Spaces.of_encryption_level t encryption_level in
  List.iter
    (fun { Frame.Range.first; last } ->
      let lowest_acked = first in
      let largest_acked = last in
      let q' =
        Q.fold
          (fun pkt_num sent q ->
            if Int64.compare pkt_num lowest_acked >= 0
               && Int64.compare pkt_num largest_acked <= 0
            then (
              if sent.ack_eliciting
              then Queue.add_seq info.acked (List.to_seq sent.frames);
              Q.remove pkt_num q)
            else q)
          info.sent
          info.sent
      in
      info.sent <- q')
    ranges

let drain_acknowledged t ~encryption_level =
  let info = Spaces.of_encryption_level t encryption_level in
  if Queue.is_empty info.acked
  then []
  else
    let qseq = Queue.to_seq info.acked in
    Queue.clear info.acked;
    List.of_seq qseq

module Constants = struct
  (* RFC 9002 Appendix A.2 / B.1 recommended constants *)
  let k_packet_threshold = 3L
  let k_time_threshold_num = 9L
  let k_time_threshold_den = 8L
  let k_granularity_ms = 1L
  let k_initial_rtt_ms = 333L
  let k_persistent_congestion_threshold = 3L
  let default_max_datagram_size = 1200

  let initial_window ~max_datagram_size =
    min (10 * max_datagram_size) (max (2 * max_datagram_size) 14720)

  let minimum_window ~max_datagram_size = 2 * max_datagram_size
end

module Debug = struct
  type rtt =
    { latest_rtt_ms : int64 option
    ; min_rtt_ms : int64 option
    ; smoothed_rtt_ms : int64
    ; rttvar_ms : int64
    ; max_ack_delay_ms : int64
    }

  type timer =
    { loss_detection_timer_ms : int64 option
    ; pto_count : int
    ; time_of_last_ack_eliciting_packet_ms : int64 option
    }

  type congestion =
    { bytes_in_flight : int
    ; congestion_window : int
    ; ssthresh : int
    ; recovery_start_time_ms : int64 option
    }

  type ecn =
    { validated : bool
    ; ect0 : int
    ; ect1 : int
    ; ce : int
    }

  type snapshot =
    { rtt : rtt
    ; timer : timer
    ; congestion : congestion
    ; ecn : ecn
    }

  let initial_snapshot =
    { rtt =
        { latest_rtt_ms = None
        ; min_rtt_ms = None
        ; smoothed_rtt_ms = Constants.k_initial_rtt_ms
        ; rttvar_ms = Int64.div Constants.k_initial_rtt_ms 2L
        ; max_ack_delay_ms = 25L
        }
    ; timer =
        { loss_detection_timer_ms = None
        ; pto_count = 0
        ; time_of_last_ack_eliciting_packet_ms = None
        }
    ; congestion =
        { bytes_in_flight = 0
        ; congestion_window =
            Constants.initial_window
              ~max_datagram_size:Constants.default_max_datagram_size
        ; ssthresh = max_int
        ; recovery_start_time_ms = None
        }
    ; ecn = { validated = false; ect0 = 0; ect1 = 0; ce = 0 }
    }

  let snapshot (_t : t) = initial_snapshot

  let record_packet_sent
        t
        ~encryption_level
        ~packet_number
        ~bytes_sent:_
        ~time_sent_ms:_
        frames
    =
    on_packet_sent t ~encryption_level ~packet_number frames

  let record_ack_received
        t
        ~encryption_level
        ~ranges
        ~ack_delay_ms:_
        ~now_ms:_
    =
    on_ack_received t ~encryption_level ~ranges

  let on_loss_detection_timeout (_t : t) ~now_ms:_ = ()

  let process_ecn
        (_t : t)
        ~newly_acked:_
        ~ect0_count:_
        ~ect1_count:_
        ~ce_count:_
    =
    ()

  let discard_space t ~encryption_level =
    let info = Spaces.of_encryption_level t encryption_level in
    info.sent <- Q.empty;
    Queue.clear info.acked
end
