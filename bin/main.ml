module Server = Dns_server.Server

let assert_no_error result =
  let open Result in
  match result with
  | Ok _ -> ()
  | Error msg -> print_endline msg

let () =
  let qname = "google.com" in
  let result = Server.find qname in
  assert_no_error result
