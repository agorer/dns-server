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
  
let of_bytestring bstr =
  let (data, _, _) = bstr in
  { data; position = 0 }
