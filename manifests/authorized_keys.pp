# @summary A defined type to represents an authorized ssh key.
#
# @param comment
#   A string to identify the ssh authorized_key on the server.  Often the hostname where the
#   key was generated
#
# @param key
#   The contents of the key, e.g. AAAA....
#
# @param key_type
#   The type of key, e.g. ssh-rsa, ssh-ed25519
define ssh::authorized_key (
  String $key_type,
  String $comment,
  String $key,
) {

}