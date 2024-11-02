open Result

let (let*) = Result.bind

let my_addr = Unix.ADDR_INET ((Unix.inet_addr_of_string "0.0.0.0"), 43210)
let real_dns_server = Unix.ADDR_INET ((Unix.inet_addr_of_string "8.8.8.8"), 53)

let find name rtype =
  let question = Packet.{ name; rtype } in
  let query_packet = Packet.make_question_packet 65432 question in
  let buf = Packet.write query_packet in
  let socket = Unix.socket Unix.PF_INET Unix.SOCK_DGRAM 0 in
  let () = Unix.bind socket my_addr in
  let flags = [] in
  let _count =
    Unix.sendto socket buf.data 0 (Bytes.length buf.data) flags real_dns_server in
  let bytes_recv = Bytes.create 512 in
  let _count, _addr = Unix.recvfrom socket bytes_recv 0 512 flags in
  let buf = Buffer.{ data = bytes_recv; position = 0 } in
  let* _buf, answer_packet = Packet.read buf in
  let () = Unix.close socket in
  print_endline (Packet.show answer_packet);
  ok ()
