open Result

let (let*) = Result.bind
    
type t = {
  data: bytes;
  position: int;
}
[@@deriving show]

let step buf steps =
  { buf with position = buf.position + steps }

let seek buf position =
  { buf with position }

let read buf =
  if buf.position >= (Bytes.length buf.data) then
    error "Reading past end of buffer"
  else
    ok ({ buf with position = buf.position + 1}, Bytes.get buf.data buf.position)

let get buf =
  if buf.position >= (Bytes.length buf.data) then
    error "Reading past end of buffer"
  else
    ok (Bytes.get buf.data buf.position)

let get_range buf start length =
  if (start + length) >= (Bytes.length buf.data) then
    error "Reading past end of buffer"
  else
    ok (Bytes.sub buf.data start length)

let read_u8 buf =
  if (buf.position +  1) > (Bytes.length buf.data) then
    error "Reading past end of buffer"
  else
    ok ({ buf with position = buf.position + 1}, Bytes.get_uint8 buf.data buf.position)

let read_u16 buf =
  if (buf.position +  2) > (Bytes.length buf.data) then
    error "Reading past end of buffer"
  else
    ok ({ buf with position = buf.position + 2}, Bytes.get_uint16_be buf.data buf.position)

let get_u16 buf =
  if (buf.position +  2) > (Bytes.length buf.data) then
    error "Reading past end of buffer"
  else
    ok (Bytes.get_uint16_be buf.data buf.position)

let read_u32 buf =
  if (buf.position + 4) > (Bytes.length buf.data) then
    error "Reading past end of buffer"
  else
    (* HACK: we are forcing the conversion, but if this code is not run
       in a 64 machine we will be in trouble *)
    let result = Int32.unsigned_to_int (
        Bytes.get_int32_be buf.data buf.position) in
    ok ({ buf with position = buf.position + 4}, (Option.get result))

module IntSet = Set.Make(Int)
[@@deriving show]

let rec read_qname buf =
  let* is_jump = is_jump buf in
  if is_jump then
    let* position = get_jump buf IntSet.empty in
    let* _, name = read_name { buf with position } "" "" in
    ok({ buf with position = position + 2}, name)
  else
    read_name buf "" ""
and get_jump buf jumps =
  let* is_jump = is_jump buf in
  if is_jump then
    let* next = get_u16 buf in
    let hint = (Char.code '\xC0') lsl 8 in
    let position = next lxor hint in
    if IntSet.mem position jumps then
      error "Cycle detected when reading qname"
    else
      get_jump { buf with position } (IntSet.add position jumps)
  else
    ok buf.position
and is_jump buf =
  let* next = get_u16 buf in
  let hint = (Char.code '\xC0') lsl 8 in
  ok ((next land hint) = hint)
and read_name buf name separator =
  let _null_byte = '\x00' in
  let* buf, next = read buf in
  match next with
  | '\x00' -> ok (buf, name)
  | length ->
    let length = Char.code length in
    let* part = get_range buf buf.position length in
    let part = separator ^ (String.of_bytes part) in
    let buf = { buf with position = buf.position + length } in
    read_name buf (name ^ part) "."
  
