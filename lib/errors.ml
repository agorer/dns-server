type packet_error =
  | Message of string
  | Code of result_code
and result_code =
  | NoError
  | Formerr
  | ServFail
  | NxDomain
  | NoTimp
  | Refused
[@@deriving show]
