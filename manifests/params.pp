# @summary This class is meant to be called from ssh.  It sets variables according to platform.
#
class ssh::params {
  $protocol = 2
  $port = [22]
  $address_family = 'any'
  $listen_addresses = [
    '127.0.0.1',
    $::hostname,
  ]
  $host_keys = [
    '/etc/ssh/ssh_host_rsa_key',
    '/etc/ssh/ssh_host_ecdsa_key',
    '/etc/ssh/ssh_host_ed25519_key',
  ]
  $syslog_facility = 'AUTHPRIV'
  $log_level = 'VERBOSE'
  $login_grace_time = 120
  $permit_root_login = 'without-password'
  $strict_modes = true
  $max_auth_tries = 3
  $print_last_log = true
  $pubkey_authentication = true
  $password_authentication = false
  $permit_empty_passwords = false
  $challenge_response_authentication = true
  $gssapi_authentication = true
  $gssapi_cleanup_credentials = true
  $use_pam = true
  $use_dns = false
  $allow_agent_forwarding = false
  $allow_tcp_forwarding = false
  $allow_stream_local_forwarding = false
  $ignore_user_known_hosts = false
  $x11_forwarding = false
  $x11_use_localhost = true
  $print_motd = false
  $tcp_keepalive = false
  $compression = false
  $client_alive_interval = 0
  $client_alive_count_max = 2
  $max_sessions = 2
  $fingerprint_hash = 'sha256'
  $ignore_rhosts = true
  $banner = 'none'
  $chroot_directory = 'none'
  $permit_tunnel = false
  $kex_algorithms = [
    'diffie-hellman-group14-sha256',
    'diffie-hellman-group16-sha512',
    'diffie-hellman-group18-sha512',
    'curve25519-sha256@libssh.org',
  ]
  $macs = [
    'umac-128-etm@openssh.com',
    'hmac-sha2-256-etm@openssh.com',
    'hmac-sha2-512-etm@openssh.com',
  ]
  $ciphers = [
    'chacha20-poly1305@openssh.com',
    'aes256-gcm@openssh.com',
    'aes128-gcm@openssh.com',
    'aes256-ctr',
    'aes192-ctr',
    'aes128-ctr',
  ]
  $disable_forwarding = false
  $accept_env = [
    'LANG',
    'LC_*',
  ]
  $debian_banner = false
  $permit_open = []
  $permit_tty = true
  $permit_user_environment = false
  $pid_file = '/run/sshd.pid'
  $max_startups = '10:30:100'
  $authorized_keys_command = 'none'
  $authorized_keys_command_user = 'none'
  $authorized_keys_file = [
    '.ssh/authorized_keys',
    '.ssh/authorized_keys2',
  ]
  $authorized_principals_file = 'none'
  $authorized_principals_command = 'none'
  $authorized_principals_command_user = 'none'

  $kerberos_authentication = false
  $kerberos_or_local_passwd = true
  $kerberos_ticket_cleanup = true
  $kerberos_get_afs_token = false
  $stream_local_bind_mask = '0177'
  $stream_local_bind_unlink = false
  $ipqos = ['lowdelay', 'throughput']
  $version_addendum = 'none'
  $force_command = 'none'
  $gateway_ports = false
  $xauth_location = '/usr/bin/xauth'
  $x11_display_offset = 10
  $kbd_interactive_authentication = true
  $gssapi_key_exchange = false
  $gssapi_store_credentials_on_rekey = false
  $gssapi_strict_acceptor_check = true
  $subsystem = []
  $trusted_user_ca_keys = 'none'
  $revoked_keys = 'none'
  $host_certificates = []
  $host_based_accepted_key_types = [
    'ecdsa-sha2-nistp256-cert-v01@openssh.com',
    'ecdsa-sha2-nistp384-cert-v01@openssh.com',
    'ecdsa-sha2-nistp521-cert-v01@openssh.com',
    'ssh-ed25519-cert-v01@openssh.com',
    'ssh-rsa-cert-v01@openssh.com',
    'ecdsa-sha2-nistp256',
    'ecdsa-sha2-nistp384',
    'ecdsa-sha2-nistp521',
    'ssh-ed25519',
    'rsa-sha2-512',
    'rsa-sha2-256',
    'ssh-rsa',
  ]
  $rekey_limit = [
    'default',
    'none',
  ]
  $pubkey_accepted_key_types = [
    'ecdsa-sha2-nistp256-cert-v01@openssh.com',
    'ecdsa-sha2-nistp384-cert-v01@openssh.com',
    'ecdsa-sha2-nistp521-cert-v01@openssh.com',
    'ssh-ed25519-cert-v01@openssh.com',
    'ssh-rsa-cert-v01@openssh.com',
    'ecdsa-sha2-nistp256',
    'ecdsa-sha2-nistp384',
    'ecdsa-sha2-nistp521',
    'ssh-ed25519',
    'rsa-sha2-512',
    'rsa-sha2-256',
    'ssh-rsa',
  ]
  $host_based_authentication = false
  $host_based_uses_name_from_packet_only = false
  $host_key_agent = 'none'
  $host_key_algorithms = [
    'ecdsa-sha2-nistp256-cert-v01@openssh.com',
    'ecdsa-sha2-nistp384-cert-v01@openssh.com',
    'ecdsa-sha2-nistp521-cert-v01@openssh.com',
    'ssh-ed25519-cert-v01@openssh.com',
    'ssh-rsa-cert-v01@openssh.com',
    'ecdsa-sha2-nistp384',
    'ecdsa-sha2-nistp521',
    'ssh-ed25519',
    'rsa-sha2-512',
    'rsa-sha2-256',
    'ssh-rsa',
  ]
  $permit_user_rc = true
  $allow_users = [
    'root'
  ]

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
