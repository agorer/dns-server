open Buffer
open Result
    
let setup input =
  {
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
  let buffer = setup input in
  let result = read_qname buffer in
  assert_name result "google.com"

let%test "qname with jump" =
  let input = "\x06google\x03com\x00\xC0\x00" in
  let buffer = setup input in
  let buffer = { buffer with position = 12 } in
  let result = read_qname buffer in
  assert_name result "google.com"

let%test "qname with cycle" =
  let input = "\xC0\x02\xC0\x00" in
  let buffer = setup input in
  let result = read_qname buffer in
  assert_error result "Cycle detected when reading qname"
