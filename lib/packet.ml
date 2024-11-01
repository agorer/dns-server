open Result

let (let*) = Result.bind

let (^^) a b = Bitstring.concat [a; b]
               
type t = {
  header: header;
  questions: question list;
  answers: record list;
  authorities: record list;
  additionals: record list;
}
and header = {
  id: int;
  qr: packet_type;              (* false for queries, true for response  *)
  opcode: int;                  (* typically always 0, see RFC1035 *)
  aa: bool;                     (* authoritative answer, does the server owns the domain *)
  rd: bool;                     (* recursion desired, should attempt to resolve recursively *)
  ra: bool;                     (* recursion available, are recursive queries allowed *)
  rcode: result_code;           (* response code, status of the response *)
}
and question = {
  name: string;                 (* domain name, will be encoded as sequence of labels *)
  rtype: record_type;
}
and record = 
  | A of preamble * ip_addr
and preamble = {
  name: string;                 (* domain name as sequence of labels *)
  rtype: record_type;           
  ttl: int;                     (* how long a record can be cached *)
  len: int;                     (* length of record type specific data *)
}
and record_type =
  | UNKNOWN of int
  | A_TYPE
and ip_addr = int * int * int * int
and result_code =
  | NoError
  | Formerr
  | ServFail
  | NxDomain
  | NoTimp
  | Refused
and packet_type =
  | Query
  | Response
[@@deriving show]

let make_question_packet id question =
  {
    header = {
      id;
      qr = Query;
      opcode = 0;
      aa = false; rd = true; ra = false;
      rcode = NoError;
    };
    questions = [question]; answers = []; authorities = []; additionals = []
}

module IntSet = Set.Make(Int)
[@@deriving show]

let rec read_qname (buf: Buffer.t) =
  let* is_jump = is_jump buf in
  if is_jump then
    let* position = get_jump buf IntSet.empty in
    let* _, name = read_name { buf with position } "" "" in
    ok({ buf with position = buf.position + 2}, name)
  else
    read_name buf "" ""
and get_jump buf jumps =
  let* is_jump = is_jump buf in
  if is_jump then
    let* next = Buffer.get_u16 buf in
    let hint = (Char.code '\xC0') lsl 8 in
    let position = next lxor hint in
    if IntSet.mem position jumps then
      error "Cycle detected when reading qname"
    else
      get_jump { buf with position } (IntSet.add position jumps)
  else
    ok buf.position
and is_jump buf =
  let* next = Buffer.get_u16 buf in
  let hint = (Char.code '\xC0') lsl 8 in
  ok ((next land hint) = hint)
and read_name buf name separator =
  let* buf, next = Buffer.read buf in
  match next with
  | '\x00' -> ok (buf, name)
  | length ->
    let length = Char.code length in
    let* part = Buffer.get_range buf buf.position length in
    let part = separator ^ (String.of_bytes part) in
    let buf = { buf with position = buf.position + length } in
    read_name buf (name ^ part) "."

let rec read buf =
  let* buf, id = Buffer.read_u16 buf in
  (* FIXME if tc = 1 message exceeds 512 and should be reissued using TCP
     here we can just create an error as not supported *)
  let* buf, qr, opcode, aa, _tc, rd, ra, _z, rcode = read_flags buf in
  let* rcode = rcode_of_int rcode in
  let* buf, question_count = Buffer.read_u16 buf in
  let* buf, answer_count = Buffer.read_u16 buf in
  let* buf, authority_count = Buffer.read_u16 buf in
  let* buf, additional_count = Buffer.read_u16 buf in
  let* buf, questions = read_questions buf question_count in
  let* buf, answers = read_records buf answer_count in
  let* buf, authorities = read_records buf authority_count in
  let* buf, additionals = read_records buf additional_count in
  ok (buf, {
      header = {
        id;
        qr = if qr then Response else Query;
        opcode; aa; rd; ra; rcode;
      };
      questions; answers; authorities; additionals;
    })
    
and read_flags buf =
  let* flags = Buffer.get_range buf buf.position 2 in
  let flags = Bitstring.bitstring_of_string (String.of_bytes flags) in
  let buf = Buffer.step buf 2 in
  match%bitstring flags with
  | {| qr:1; opcode:4; aa:1; tc:1; rd:1; ra:1; z:3; rcode:4 |} ->
    ok (buf, qr, opcode, aa, tc, rd, ra, z, rcode)
  | {| _ |} -> error "Invalid flags in packet"

and rcode_of_int = function
  | 0 -> ok NoError
  | 1 -> ok Formerr
  | 2 -> ok ServFail
  | 3 -> ok NxDomain
  | 4 -> ok NoTimp
  | 5 -> ok Refused
  | other -> error ("Invalid result code: " ^ (string_of_int other))

and read_questions buf count =
  let rec aux buf count questions =
    match count with
    | 0 -> ok (buf, questions)
    | n -> 
      let* buf, question = read_question buf in
      aux buf (n - 1) (questions @ [question])
  in
  aux buf count []

and read_question buf =
  let* buf, name = read_qname buf in
  let* buf, rtype = read_record_type buf in
  let* buf, _class = Buffer.read_u16 buf in
  ok (buf, { name; rtype })

and read_records buf count =
  let rec aux buf count records =
    match count with
    | 0 -> ok (buf, records)
    | n -> 
      let* buf, record = read_record buf in
      aux buf (n - 1) (records @ [record])
  in
  aux buf count []

and read_record_type buf =
  let* buf, rtype = Buffer.read_u16 buf in
  match rtype with
  | 1 -> ok (buf, A_TYPE)
  | other -> ok (buf, UNKNOWN other)

and read_record buf =
  let* buf, name = read_qname buf in
  let* buf, rtype = read_record_type buf in
  let* buf, _class = Buffer.read_u16 buf in
  let* buf, ttl = Buffer.read_u32 buf in
  let* buf, len = Buffer.read_u16 buf in
  let* buf, ip = read_ip_address buf in (* FIXME this only works for A records *)
  ok (buf, A({name; rtype; ttl; len}, ip))

and read_ip_address buf =
  let* buf, part1 = Buffer.read_u8 buf in
  let* buf, part2 = Buffer.read_u8 buf in
  let* buf, part3 = Buffer.read_u8 buf in
  let* buf, part4 = Buffer.read_u8 buf in
  ok (buf, (part1, part2, part3, part4))

let rec write packet =
  let header = write_header packet in
  let questions = write_questions packet.questions in
  let answers = write_records packet.answers in
  let authorities = write_records packet.authorities in
  let additionals = write_records packet.additionals in
  Buffer.of_bytestring (header ^^ questions ^^ answers ^^ authorities ^^ additionals)

and write_header packet =
  let id = packet.header.id in
  let qr = bool_of_packet_type packet.header.qr in
  let opcode = packet.header.opcode in
  let aa = packet.header.aa in
  let tc = false in                 (* Not dealing with truncated packages here *)
  let rd = packet.header.rd in
  let ra = packet.header.ra in
  let z = 0 in                  (* Not dealing with DNSSEC here *)
  let rcode = 0 in
  let qd_count = List.length packet.questions in
  let an_count = List.length packet.answers in
  let ns_count = List.length packet.authorities in
  let ar_count = List.length packet.additionals in
  let%bitstring bits = {| id:16; qr:1; opcode:4; aa:1; tc:1; rd:1; ra:1; z:3;
       rcode:4; qd_count:16; an_count:16; ns_count:16; ar_count:16 |} in
  bits

and write_questions questions =
  List.fold_left
    (fun acc question ->  acc ^^ (write_question question))
    Bitstring.empty_bitstring
    questions

and write_question question =
  let name = write_qname question.name in
  let len = Bitstring.bitstring_length name in
  let rtype = int_of_record_type question.rtype in
  let rclass = 1 in             (* The class, in practice always set to 1 *)
  let%bitstring bits = {| name:len:bitstring; rtype:16; rclass:16 |} in
  bits

and write_qname name =
  let parts = String.split_on_char '.' name in
  let qname = List.fold_left
    (fun acc part ->
      let len = String.length part in
      let%bitstring bits = {| len:8; part:len * 8:string |} in
      acc ^^ bits)
    Bitstring.empty_bitstring
    parts
  in
  qname ^^ (Bitstring.bitstring_of_string "\x00")

and write_records records =
  List.fold_left
    (fun acc record ->  acc ^^ (write_record record))
    Bitstring.empty_bitstring
    records

and write_record record =
  match record with
  | A (preamble, ip) -> (write_preamble preamble) ^^ (write_ip ip)

and write_preamble (preamble: preamble) =
  let name = write_qname preamble.name in
  let name_len = Bitstring.bitstring_length name in
  let rtype = int_of_record_type preamble.rtype in
  let rclass = 1 in             (* The class, in practice always set to 1 *)
  let ttl = Int32.of_int preamble.ttl in
  let len = preamble.len in
  let%bitstring bits = {| name:name_len:bitstring; rtype:16; rclass:16; ttl:32; len:16 |} in
  bits

and write_ip ip =
  let p1, p2, p3, p4 = ip in
  let%bitstring bits = {| p1:8; p2:8; p3:8; p4:8 |} in
  bits
          
and bool_of_packet_type typ =
  match typ with
  | Query -> false
  | Response -> true

and int_of_record_type typ =
  match typ with
  | A_TYPE -> 1
  | UNKNOWN other -> other

