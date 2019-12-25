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
  $permit_root_login = 'without-password'
  $strict_modes = 'yes'
  $max_auth_tries = 3
  $pubkey_authentication = 'yes'
  $rsa_authentication = 'yes'
  $authorized_keys_file = '.ssh/authorized_keys'
  $password_authentication = false
  $permit_empty_passwords = false
  $challenge_response_authentication = 'yes'
  $gssapi_authentication = 'yes'
  $gssapi_cleanup_credentials = 'yes'
  $use_pam = true
  $use_dns = false
  $allow_agent_forwarding = true
  $allow_tcp_forwarding = true
  $allow_stream_local_forwarding = false
  $ignore_user_known_hosts = false
  $x11_forwarding = false
  $x11_use_localhost = true
  $print_motd = false
  $tcp_keepalive = true
  $compression = false
  $client_alive_interval = 0
  $client_alive_count_max = 2
  $max_sessions = 2
  $fingerprint_hash = 'sha256'
  $ignore_rhosts = true
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
  $disable_forwarding = false
  $accept_env = [
    "LANG",
    "LC_*",
  ]
  $debian_banner = false
  $permit_open = []
  $permit_tty = true
  $permit_user_environment = false

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