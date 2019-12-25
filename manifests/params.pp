# == Class ssh::params
#
# This class is meant to be called from ssh.
# It sets variables according to platform.
#
class ssh::params {
  $protocol = 2
  $port = [22]
  $address_family = 'any'
  $listen_addresses = [
    '127.0.0.1',
    $hostname,
  ]
  $host_keys = [
    '/etc/ssh/ssh_host_rsa_key',
    '/etc/ssh/ssh_host_dsa_key',
    '/etc/ssh/ssh_host_ecdsa_key',
    '/etc/ssh/ssh_host_ed25519_key',
  ]
  $syslog_facility = 'AUTHPRIV'
  $log_level = 'INFO'
  $login_grace_time = 120
  $permit_root_login = 'no'
  $strict_modes = 'yes'
  $max_auth_tries = 3
  $pubkey_authentication = 'yes'
  $rsa_authentication = 'yes'
  $authorized_keys_file = '.ssh/authorized_keys'
  $password_authentication = 'no'
  $permit_empty_passwords = 'no'
  $challenge_response_authentication = 'yes'
  $gssapi_authentication = 'yes'
  $gssapi_cleanup_credentials = 'yes'
  $use_pam = 'yes'
  $use_dns = 'no'
  $allow_agent_forwarding = 'yes'
  $allow_tcp_forwarding = 'yes'
  $x11_forwarding = 'no'
  $x11_use_localhost = 'yes'
  $print_motd = 'no'
  $tcp_keepalive = 'yes'
  $compression = 'no'
  $client_alive_interval = 0
  $client_alive_count_max = 2
  $max_sessions = 2
  $banner = 'none'
  $chroot_directory = 'none'
  $permit_tunnel = 'no'
  $kex_algorithms = [
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "curve25519-sha256@libssh.org",
  ]
  $macs = [
    "umac-128-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
  ]
  $ciphers = [
    "chacha20-poly1305@openssh.com",
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
    "aes256-ctr",
    "aes192-ctr",
    "aes128-ctr",
  ]
  $disable_forwarding = no


  case $::osfamily {
    'Debian': {
      $package_name = 'ssh'
      $service_name = 'ssh'
    }
    'RedHat', 'Amazon': {
      $package_name = 'ssh'
      $service_name = 'ssh'
    }
    default: {
      fail("${::operatingsystem} not supported")
    }
  }
}