open Result
open Errors

let (let*) = Result.bind

let make_addr ip port =
  Unix.ADDR_INET ((Unix.inet_addr_of_string ip), port)
    
let lookup name rtype =
  let open Packet in
  let question = { name; rtype } in
  let query_packet = make_question_packet 65432 question in
  let buf = Packet.write query_packet in
  let socket = Unix.socket Unix.PF_INET Unix.SOCK_DGRAM 0 in
  let my_addr = make_addr "0.0.0.0" 43210 in
  let () = Unix.bind socket my_addr in
  let flags = [] in
  let support_server = make_addr "8.8.8.8" 53 in
  let _count =
    Unix.sendto socket buf.data 0 (Bytes.length buf.data) flags support_server in
  let bytes_recv = Bytes.create 512 in
  let _count, _addr = Unix.recvfrom socket bytes_recv 0 512 flags in
  let buf = Buffer.{ data = bytes_recv; position = 0 } in
  let* _buf, response_packet = Packet.read buf in
  let () = Unix.close socket in
  ok (response_packet)

let rec wait_for_queries socket =
  let src_addr, bytes_recv = receive_query socket in
  let _ = match handle_query bytes_recv with
    | Ok (out_buf) -> send_reply socket out_buf src_addr
    | Error error ->
      let id = (extract_id bytes_recv) in
      send_error socket id error src_addr in
  wait_for_queries socket

and receive_query socket =
  let bytes_recv = Bytes.create 512 in
  let count, src_addr = Unix.recvfrom socket bytes_recv 0 512 [] in
  let bytes_recv = Bytes.sub bytes_recv 0 count in
  src_addr, bytes_recv

and handle_query bytes_recv =
  let open Packet in
  let buf = Buffer.{ data = bytes_recv; position = 0 } in
  let* _buf, request = Packet.read buf in
  let* question = extract_question request in
  let* packet = lookup question.name question.rtype in
  let out_packet =
    Packet.make_response_packet request.header.id question packet.answers in
  let buf = Packet.write out_packet in
  ok (buf)

and extract_question request : (Packet.question, packet_error) result =
  let count = List.length request.questions in
  if count <> 1 then
    error (Code Errors.Formerr)
  else
    ok (List.hd request.questions)

and send_reply socket buf src_addr =
  let _ = Unix.sendto socket buf.data 0 (Bytes.length buf.data) [] src_addr in ()

and extract_id bytes_recv =
  let buf = Buffer.{ data = bytes_recv; position = 0 } in
  let result = Buffer.read_u16 buf in
  match result with
  | Ok (_buf, id) -> id
  | Error _ -> -1

and send_error socket id error src_addr =
  let () = print_endline (Errors.show_packet_error error) in
  let code = match error with
    | Message _ -> Errors.Formerr
    | Code code -> code
  in
  let packet = Packet.make_error_packet id code in
  let buf = Packet.write packet in
  let _ = Unix.sendto socket buf.data 0 (Bytes.length buf.data) [] src_addr in ()


