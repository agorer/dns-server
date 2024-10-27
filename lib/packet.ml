open Result

let (let*) = Result.bind
               
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
  | UNKNOWN
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
        qr = if qr = 0 then Query else Response;
        opcode;
        aa = bool_of_int aa;
        rd = bool_of_int rd;
        ra = bool_of_int ra;
        rcode;
      };
      questions; answers; authorities; additionals;
    })
    
and read_flags buf =
  let* flags = Buffer.get_range buf buf.position 2 in
  let flags = Bytestring.of_string (String.of_bytes flags) in
  let buf = Buffer.step buf 2 in
  match%b flags with
  | {| qr::1, opcode::4, aa::1, tc::1, rd::1, ra::1, z::3, rcode::4 |} ->
    ok (buf, qr, opcode, aa, tc, rd, ra, z, rcode)
  | {| _rest |} -> error "Invalid flags in packet"

and bool_of_int = function
  | 0 -> false
  | _ -> true
    
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
  let* buf, name = Buffer.read_qname buf in
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
  | _ -> ok (buf, UNKNOWN)

and read_record buf =
  let* buf, name = Buffer.read_qname buf in
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
