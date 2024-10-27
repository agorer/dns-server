(lang dune 3.16)

(name dns_server)

(generate_opam_files true)

(source
 (github agorer/dns-server))

(authors "Juanjo Molinero")

(license MIT)

(documentation https://github.com/EmilHernvall/dnsguide/blob/master/README.md)

(package
 (name dns_server)
 (synopsis "Simple DNS server")
 (depends bytestring ocaml dune)
 (tags
  (net udp dns)))

