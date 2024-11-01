open Result
open Packet
    
let setup_buffer input =
  Buffer.{
    data = Bytes.of_string input;
    position = 0
  }

let assert_name result name =
  match result with
  | Ok (_, qname) -> qname = name
  | Error _ -> false

let assert_error result expected_msg =
  match result with
  | Ok _ -> print_endline "ok"; false
  | Error msg -> msg = expected_msg

let%test "qname without jumps" =
  let input = "\x06google\x03com\x00" in
  let buffer = setup_buffer input in
  let result = Packet.read_qname buffer in
  assert_name result "google.com"

let%test "qname with jump" =
  let input = "\x06google\x03com\x00\xC0\x00" in
  let buffer = setup_buffer input in
  let buffer = { buffer with position = 12 } in
  let result = Packet.read_qname buffer in
  assert_name result "google.com"

let%test "qname with cycle" =
  let input = "\xC0\x02\xC0\x00" in
  let buffer = setup_buffer input in
  let result = Packet.read_qname buffer in
  assert_error result "Cycle detected when reading qname"


let setup path =
  let ic = open_in_bin path in
  let data = Bytes.of_string (In_channel.input_all ic) in
  Buffer.{ data; position = 0 }

let assert_no_error result =
  match result with
  | Error msg -> failwith msg
  | Ok (_buf, packet) -> packet

let%test "read packet" =
  let buf = setup "../test/response_packet.txt" in
  let result = read buf in
  let packet = assert_no_error result in
  packet.header.rcode = NoError
