module Server = Dns_server.Server
module Packet = Dns_server.Packet

let assert_no_error result =
  let open Result in
  match result with
  | Ok _ -> ()
  | Error msg -> print_endline msg

let () =
  let qname = "yahoo.com" in
  let rtype = Packet.MX' in
  let result = Server.find qname rtype in
  assert_no_error result
