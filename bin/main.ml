module Server = Dns_server.Server

let () =
  let socket = Unix.socket Unix.PF_INET Unix.SOCK_DGRAM 0 in
  let my_addr = Server.make_addr (0,0,0,0) 2053 in
  let () = Unix.bind socket my_addr in
  Server.wait_for_queries socket
