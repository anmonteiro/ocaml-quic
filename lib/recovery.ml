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

type sent =
  { frames : Frame.t list
  ; packet_number : int64
  ; ack_eliciting : bool
  ; in_flight : bool
  ; sent_bytes : int
  ; time_sent_ms : int64
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
  ; lost : Frame.t list Queue.t
  ; mutable ack_eliciting_in_flight : int
  ; mutable time_of_last_ack_eliciting_packet_ms : int64 option
  }

type rtt =
  { mutable latest_rtt_ms : int64 option
  ; mutable min_rtt_ms : int64 option
  ; mutable smoothed_rtt_ms : int64
  ; mutable rttvar_ms : int64
  ; mutable max_ack_delay_ms : int64
  }

type timer =
  { mutable loss_detection_timer_ms : int64 option
  ; mutable pto_count : int
  ; mutable pto_probe_count : int
  }

type congestion =
  { mutable bytes_in_flight : int
  ; mutable congestion_window : int
  ; mutable ssthresh : int
  ; mutable recovery_start_time_ms : int64 option
  }

type ecn =
  { mutable validated : bool
  ; mutable ect0 : int
  ; mutable ect1 : int
  ; mutable ce : int
  }

type t =
  { spaces : info Spaces.t
  ; rtt : rtt
  ; timer : timer
  ; congestion : congestion
  ; ecn : ecn
  ; max_datagram_size : int
  ; mutable implicit_now_ms : int64
  }

let max_int64 a b = if Int64.compare a b >= 0 then a else b
let min_int64 a b = if Int64.compare a b <= 0 then a else b
let abs_int64 x = if Int64.compare x 0L < 0 then Int64.neg x else x

let mul_div_floor x num den = Int64.div (Int64.mul x num) den

let packet_is_in_flight frames =
  Frame.is_any_ack_eliciting frames
  || List.exists (function Frame.Padding _ -> true | _ -> false) frames

let is_retransmittable_frame = function
  | Frame.Ack _ | Padding _ -> false
  | _ -> true

let retransmittable_frames frames = List.filter is_retransmittable_frame frames

let pto_base_ms t =
  Int64.add
    t.rtt.smoothed_rtt_ms
    (Int64.add
       (max_int64
          (Int64.mul 4L t.rtt.rttvar_ms)
          Constants.k_granularity_ms)
       t.rtt.max_ack_delay_ms)

let set_loss_detection_timer t =
  if t.congestion.bytes_in_flight <= 0
  then t.timer.loss_detection_timer_ms <- None
  else
    let backoff = Int64.shift_left 1L t.timer.pto_count in
    let timeout = Int64.mul (pto_base_ms t) backoff in
    let min_timeout =
      Spaces.to_list t.spaces
      |> List.fold_left
           (fun acc (_level, info) ->
              if info.ack_eliciting_in_flight > 0
              then
                match info.time_of_last_ack_eliciting_packet_ms with
                | None -> acc
                | Some last_ack_eliciting_time ->
                  let space_timeout = Int64.add last_ack_eliciting_time timeout in
                  (match acc with
                  | None -> Some space_timeout
                  | Some current -> Some (Int64.min current space_timeout))
              else acc)
           None
    in
    t.timer.loss_detection_timer_ms <- min_timeout

let subtract_bytes_in_flight t n =
  t.congestion.bytes_in_flight <- max 0 (t.congestion.bytes_in_flight - n)

let in_recovery_period t ~time_sent_ms =
  match t.congestion.recovery_start_time_ms with
  | None -> false
  | Some recovery_start_time -> Int64.compare time_sent_ms recovery_start_time <= 0

let collapse_to_min_window t =
  t.congestion.congestion_window <-
    Constants.minimum_window ~max_datagram_size:t.max_datagram_size

let on_packets_acked t ~bytes_acked =
  if bytes_acked <= 0
  then ()
  else if t.congestion.congestion_window < t.congestion.ssthresh
  then
    t.congestion.congestion_window <-
      t.congestion.congestion_window + bytes_acked
  else
    let denom = max 1 t.congestion.congestion_window in
    let incr =
      max
        1
        ((t.max_datagram_size * bytes_acked) / denom)
    in
    t.congestion.congestion_window <- t.congestion.congestion_window + incr

let update_rtt_estimate t ~latest_rtt_ms ~ack_delay_ms =
  let previous_min_rtt = t.rtt.min_rtt_ms in
  t.rtt.latest_rtt_ms <- Some latest_rtt_ms;
  let min_rtt =
    match previous_min_rtt with
    | None -> latest_rtt_ms
    | Some old -> min_int64 old latest_rtt_ms
  in
  t.rtt.min_rtt_ms <- Some min_rtt;
  match previous_min_rtt with
  | None ->
    t.rtt.smoothed_rtt_ms <- latest_rtt_ms;
    t.rtt.rttvar_ms <- Int64.div latest_rtt_ms 2L
  | Some _ ->
    let clamped_ack_delay = min_int64 ack_delay_ms t.rtt.max_ack_delay_ms in
    let adjusted_rtt =
      if Int64.compare (Int64.sub latest_rtt_ms min_rtt) clamped_ack_delay > 0
      then Int64.sub latest_rtt_ms clamped_ack_delay
      else latest_rtt_ms
    in
    let rttvar_sample = abs_int64 (Int64.sub t.rtt.smoothed_rtt_ms adjusted_rtt) in
    t.rtt.rttvar_ms <-
      Int64.div (Int64.add (Int64.mul 3L t.rtt.rttvar_ms) rttvar_sample) 4L;
    t.rtt.smoothed_rtt_ms <-
      Int64.div
        (Int64.add (Int64.mul 7L t.rtt.smoothed_rtt_ms) adjusted_rtt)
        8L

let maybe_persistent_congestion t lost_packets =
  let times =
    List.fold_left
      (fun acc pkt -> if pkt.in_flight then pkt.time_sent_ms :: acc else acc)
      []
      lost_packets
  in
  match times with
  | [] -> false
  | first :: rest ->
    let oldest, newest =
      List.fold_left
        (fun (oldest, newest) ts -> min_int64 oldest ts, max_int64 newest ts)
        (first, first)
        rest
    in
    let duration = Int64.sub newest oldest in
    let threshold =
      Int64.mul (pto_base_ms t) Constants.k_persistent_congestion_threshold
    in
    Int64.compare duration threshold >= 0

let on_congestion_event t ~now_ms ~lost_packets =
  let newest_lost_time =
    List.fold_left
      (fun acc pkt ->
         if pkt.in_flight
         then
           match acc with
           | None -> Some pkt.time_sent_ms
           | Some cur -> Some (max_int64 cur pkt.time_sent_ms)
         else acc)
      None
      lost_packets
  in
  match newest_lost_time with
  | None -> ()
  | Some newest ->
    let in_recovery =
      match t.congestion.recovery_start_time_ms with
      | None -> false
      | Some recovery_start_time -> Int64.compare newest recovery_start_time <= 0
    in
    if not in_recovery
    then (
      t.congestion.recovery_start_time_ms <- Some now_ms;
      t.congestion.ssthresh <-
        max
          (t.congestion.congestion_window / 2)
          (Constants.minimum_window ~max_datagram_size:t.max_datagram_size);
      t.congestion.congestion_window <- t.congestion.ssthresh);
    if maybe_persistent_congestion t lost_packets
    then collapse_to_min_window t

let is_acked packet_number ranges =
  List.exists
    (fun { Frame.Range.first; last } ->
       Int64.compare packet_number first >= 0
       && Int64.compare packet_number last <= 0)
    ranges

let detect_lost_packets t ~encryption_level ~now_ms ~largest_newly_acked =
  match largest_newly_acked with
  | None -> []
  | Some largest_newly_acked ->
    let info = Spaces.of_encryption_level t.spaces encryption_level in
    let latest_rtt =
      match t.rtt.latest_rtt_ms with
      | Some latest -> latest
      | None -> t.rtt.smoothed_rtt_ms
    in
    let loss_delay =
      max_int64
        (mul_div_floor
           (max_int64 latest_rtt t.rtt.smoothed_rtt_ms)
           Constants.k_time_threshold_num
           Constants.k_time_threshold_den)
        Constants.k_granularity_ms
    in
    let lost_send_time = Int64.sub now_ms loss_delay in
    let lost_packets_rev = ref [] in
    let sent' =
      Q.fold
        (fun packet_number packet acc ->
           let lost_by_packet_threshold =
             Int64.compare
               (Int64.add packet_number Constants.k_packet_threshold)
               largest_newly_acked
             <= 0
           in
           let eligible_for_time_threshold =
             Int64.compare packet_number largest_newly_acked <= 0
           in
           let lost_by_time_threshold =
             eligible_for_time_threshold
             && Int64.compare packet.time_sent_ms lost_send_time <= 0
           in
           if lost_by_packet_threshold || lost_by_time_threshold
           then (
             if packet.in_flight
             then subtract_bytes_in_flight t packet.sent_bytes;
             if packet.in_flight && packet.ack_eliciting
             then
               info.ack_eliciting_in_flight <-
                 max 0 (info.ack_eliciting_in_flight - 1);
             lost_packets_rev := packet :: !lost_packets_rev;
             Q.remove packet_number acc)
           else acc)
        info.sent
        info.sent
    in
    info.sent <- sent';
    List.rev !lost_packets_rev

let create ?(max_datagram_size = Constants.default_max_datagram_size) () =
  let new_info () =
    { sent = Q.empty
    ; acked = Queue.create ()
    ; lost = Queue.create ()
    ; ack_eliciting_in_flight = 0
    ; time_of_last_ack_eliciting_packet_ms = None
    }
  in
  { spaces =
      Spaces.create
        ~initial:(new_info ())
        ~handshake:(new_info ())
        ~application_data:(new_info ())
  ; rtt =
      { latest_rtt_ms = None
      ; min_rtt_ms = None
      ; smoothed_rtt_ms = Constants.k_initial_rtt_ms
      ; rttvar_ms = Int64.div Constants.k_initial_rtt_ms 2L
      ; max_ack_delay_ms = 25L
      }
  ; timer =
      { loss_detection_timer_ms = None
      ; pto_count = 0
      ; pto_probe_count = 0
      }
  ; congestion =
      { bytes_in_flight = 0
      ; congestion_window = Constants.initial_window ~max_datagram_size
      ; ssthresh = max_int
      ; recovery_start_time_ms = None
      }
  ; ecn = { validated = false; ect0 = 0; ect1 = 0; ce = 0 }
  ; max_datagram_size
  ; implicit_now_ms = 0L
  }

let next_implicit_now_ms t =
  let now = t.implicit_now_ms in
  t.implicit_now_ms <- Int64.add now 1L;
  now

let record_packet_sent
      t
      ~encryption_level
      ~packet_number
      ~bytes_sent
      ~time_sent_ms
      frames
  =
  let info = Spaces.of_encryption_level t.spaces encryption_level in
  let ack_eliciting = Frame.is_any_ack_eliciting frames in
  let in_flight = packet_is_in_flight frames in
  if not in_flight
  then ()
  else (
  let sent_bytes = if in_flight then max 1 bytes_sent else 0 in
  let sent =
    { packet_number
    ; frames
    ; ack_eliciting
    ; in_flight
    ; sent_bytes
    ; time_sent_ms
    }
  in
  assert (not (Q.mem packet_number info.sent));
  info.sent <- Q.add packet_number sent info.sent;
  if in_flight && ack_eliciting
  then info.ack_eliciting_in_flight <- info.ack_eliciting_in_flight + 1;
  if in_flight
  then t.congestion.bytes_in_flight <- t.congestion.bytes_in_flight + sent_bytes;
  if in_flight && t.timer.pto_probe_count > 0
  then t.timer.pto_probe_count <- t.timer.pto_probe_count - 1;
  if ack_eliciting
  then info.time_of_last_ack_eliciting_packet_ms <- Some time_sent_ms;
  set_loss_detection_timer t)

let record_ack_eliciting_in_flight_packet_sent
      t
      ~encryption_level
      ~packet_number
      ~bytes_sent
      ~time_sent_ms
      frames
  =
  let info = Spaces.of_encryption_level t.spaces encryption_level in
  let sent_bytes = max 1 bytes_sent in
  let sent =
    { packet_number
    ; frames
    ; ack_eliciting = true
    ; in_flight = true
    ; sent_bytes
    ; time_sent_ms
    }
  in
  assert (not (Q.mem packet_number info.sent));
  info.sent <- Q.add packet_number sent info.sent;
  info.ack_eliciting_in_flight <- info.ack_eliciting_in_flight + 1;
  t.congestion.bytes_in_flight <- t.congestion.bytes_in_flight + sent_bytes;
  if t.timer.pto_probe_count > 0
  then t.timer.pto_probe_count <- t.timer.pto_probe_count - 1;
  info.time_of_last_ack_eliciting_packet_ms <- Some time_sent_ms;
  set_loss_detection_timer t

let on_packet_sent t ~encryption_level ~packet_number frames =
  let time_sent_ms = next_implicit_now_ms t in
  let bytes_sent = if packet_is_in_flight frames then t.max_datagram_size else 0 in
  record_packet_sent
    t
    ~encryption_level
    ~packet_number
    ~bytes_sent
    ~time_sent_ms
    frames

let record_ack_received
      t
      ~encryption_level
      ~ranges
      ~ack_delay_ms
      ~now_ms
  =
  let info = Spaces.of_encryption_level t.spaces encryption_level in
  let acked_packets_rev = ref [] in
  let sent' =
    Q.fold
      (fun packet_number packet acc ->
         if is_acked packet_number ranges
         then (
           acked_packets_rev := packet :: !acked_packets_rev;
           if packet.ack_eliciting
           then Queue.add_seq info.acked (List.to_seq packet.frames);
           if packet.in_flight && packet.ack_eliciting
           then
             info.ack_eliciting_in_flight <-
               max 0 (info.ack_eliciting_in_flight - 1);
           if packet.in_flight
           then subtract_bytes_in_flight t packet.sent_bytes;
           Q.remove packet_number acc)
         else acc)
      info.sent
      info.sent
  in
  info.sent <- sent';

  let acked_packets = List.rev !acked_packets_rev in
  let largest_acked_packet =
    List.fold_left
      (fun acc pkt ->
         match acc with
         | None -> Some pkt
         | Some cur ->
           if Int64.compare pkt.packet_number cur.packet_number > 0
           then Some pkt
           else acc)
      None
      acked_packets
  in

  (match largest_acked_packet with
  | Some pkt when pkt.ack_eliciting ->
    let latest_rtt = max_int64 0L (Int64.sub now_ms pkt.time_sent_ms) in
    update_rtt_estimate t ~latest_rtt_ms:latest_rtt ~ack_delay_ms
  | Some _ | None -> ());

  let bytes_acked_for_cc =
    List.fold_left
      (fun acc pkt ->
         if pkt.in_flight && not (in_recovery_period t ~time_sent_ms:pkt.time_sent_ms)
         then acc + pkt.sent_bytes
         else acc)
      0
      acked_packets
  in
  on_packets_acked t ~bytes_acked:bytes_acked_for_cc;

  let largest_newly_acked =
    match largest_acked_packet with
    | None -> None
    | Some pkt -> Some pkt.packet_number
  in
  let lost_packets =
    detect_lost_packets t ~encryption_level ~now_ms ~largest_newly_acked
  in
  List.iter
    (fun packet ->
       let retransmittable = retransmittable_frames packet.frames in
       if retransmittable <> [] then Queue.add retransmittable info.lost)
    lost_packets;
  if lost_packets <> []
  then on_congestion_event t ~now_ms ~lost_packets;

  if acked_packets <> []
  then (
    t.timer.pto_count <- 0;
    t.timer.pto_probe_count <- 0);
  set_loss_detection_timer t

let on_ack_received t ~encryption_level ~ranges =
  let info = Spaces.of_encryption_level t.spaces encryption_level in
  let sent' =
    Q.fold
      (fun packet_number packet acc ->
         if is_acked packet_number ranges
         then (
           if packet.ack_eliciting
           then Queue.add_seq info.acked (List.to_seq packet.frames);
           if packet.in_flight && packet.ack_eliciting
           then
             info.ack_eliciting_in_flight <-
               max 0 (info.ack_eliciting_in_flight - 1);
           if packet.in_flight
           then subtract_bytes_in_flight t packet.sent_bytes;
           Q.remove packet_number acc)
         else acc)
      info.sent
      info.sent
  in
  info.sent <- sent';
  set_loss_detection_timer t

let can_send t ~bytes =
  bytes <= 0
  || t.congestion.bytes_in_flight + bytes <= t.congestion.congestion_window
  || t.timer.pto_probe_count > 0

let on_loss_detection_timeout t ~now_ms =
  if t.congestion.bytes_in_flight > 0
  then (
    t.timer.pto_count <- t.timer.pto_count + 1;
    t.timer.pto_probe_count <- 2;
    if t.timer.pto_count >= Int64.to_int Constants.k_persistent_congestion_threshold
    then collapse_to_min_window t;
    t.congestion.recovery_start_time_ms <- Some now_ms);
  set_loss_detection_timer t

let process_ecn t ~newly_acked:_ ~ect0_count ~ect1_count ~ce_count =
  let old_ect0 = t.ecn.ect0 in
  let old_ect1 = t.ecn.ect1 in
  let old_ce = t.ecn.ce in
  let monotonic = ect0_count >= old_ect0 && ect1_count >= old_ect1 && ce_count >= old_ce in
  if monotonic then t.ecn.validated <- true;
  if t.ecn.validated && ce_count > old_ce
  then (
    t.congestion.recovery_start_time_ms <- Some (next_implicit_now_ms t);
    t.congestion.ssthresh <-
      max
        (t.congestion.congestion_window / 2)
        (Constants.minimum_window ~max_datagram_size:t.max_datagram_size);
    t.congestion.congestion_window <- t.congestion.ssthresh);
  t.ecn.ect0 <- ect0_count;
  t.ecn.ect1 <- ect1_count;
  t.ecn.ce <- ce_count

let discard_space t ~encryption_level =
  let info = Spaces.of_encryption_level t.spaces encryption_level in
  let removed_in_flight =
    Q.fold
      (fun _ pkt acc -> if pkt.in_flight then acc + pkt.sent_bytes else acc)
      0
      info.sent
  in
  subtract_bytes_in_flight t removed_in_flight;
  info.sent <- Q.empty;
  info.ack_eliciting_in_flight <- 0;
  Queue.clear info.acked;
  Queue.clear info.lost;
  info.time_of_last_ack_eliciting_packet_ms <- None;
  set_loss_detection_timer t

let drain_acknowledged t ~encryption_level =
  let info = Spaces.of_encryption_level t.spaces encryption_level in
  if Queue.is_empty info.acked
  then []
  else
    let qseq = Queue.to_seq info.acked in
    Queue.clear info.acked;
    List.of_seq qseq

let drain_lost t ~encryption_level =
  let info = Spaces.of_encryption_level t.spaces encryption_level in
  if Queue.is_empty info.lost
  then []
  else
    let qseq = Queue.to_seq info.lost in
    Queue.clear info.lost;
    List.of_seq qseq

let pto_probe_packets t ~encryption_level ~max_packets =
  if max_packets <= 0
  then []
  else
    let info = Spaces.of_encryption_level t.spaces encryption_level in
    Q.to_list info.sent
    |> List.sort (fun (pn1, _) (pn2, _) -> Int64.compare pn1 pn2)
    |> List.fold_left
         (fun acc (_packet_number, packet) ->
            if List.length acc >= max_packets
            then acc
            else
              let retransmittable = retransmittable_frames packet.frames in
              if packet.ack_eliciting && retransmittable <> []
              then retransmittable :: acc
              else acc)
         []
    |> List.rev

module Debug = struct
  type nonrec rtt = rtt
  type nonrec timer = timer
  type nonrec congestion = congestion
  type nonrec ecn = ecn

  type snapshot =
    { rtt : rtt
    ; timer : timer
    ; congestion : congestion
    ; ecn : ecn
    }

  let info t ~encryption_level = Spaces.of_encryption_level t.spaces encryption_level

  let snapshot (t : t) =
    { rtt =
        { latest_rtt_ms = t.rtt.latest_rtt_ms
        ; min_rtt_ms = t.rtt.min_rtt_ms
        ; smoothed_rtt_ms = t.rtt.smoothed_rtt_ms
        ; rttvar_ms = t.rtt.rttvar_ms
        ; max_ack_delay_ms = t.rtt.max_ack_delay_ms
        }
    ; timer =
        { loss_detection_timer_ms = t.timer.loss_detection_timer_ms
        ; pto_count = t.timer.pto_count
        ; pto_probe_count = t.timer.pto_probe_count
        }
    ; congestion =
        { bytes_in_flight = t.congestion.bytes_in_flight
        ; congestion_window = t.congestion.congestion_window
        ; ssthresh = t.congestion.ssthresh
        ; recovery_start_time_ms = t.congestion.recovery_start_time_ms
        }
    ; ecn =
        { validated = t.ecn.validated
        ; ect0 = t.ecn.ect0
        ; ect1 = t.ecn.ect1
        ; ce = t.ecn.ce
        }
    }

  let record_packet_sent
        t
        ~encryption_level
        ~packet_number
        ~bytes_sent
        ~time_sent_ms
        frames
    =
    record_packet_sent
      t
      ~encryption_level
      ~packet_number
      ~bytes_sent
      ~time_sent_ms
      frames

  let record_ack_received
        t
        ~encryption_level
        ~ranges
        ~ack_delay_ms
        ~now_ms
    =
    record_ack_received
      t
      ~encryption_level
      ~ranges
      ~ack_delay_ms
      ~now_ms

  let record_ack_eliciting_in_flight_packet_sent
        t
        ~encryption_level
        ~packet_number
        ~bytes_sent
        ~time_sent_ms
        frames
    =
    record_ack_eliciting_in_flight_packet_sent
      t
      ~encryption_level
      ~packet_number
      ~bytes_sent
      ~time_sent_ms
      frames

  let on_loss_detection_timeout t ~now_ms = on_loss_detection_timeout t ~now_ms

  let process_ecn t ~newly_acked ~ect0_count ~ect1_count ~ce_count =
    process_ecn t ~newly_acked ~ect0_count ~ect1_count ~ce_count

  let discard_space t ~encryption_level = discard_space t ~encryption_level
end
