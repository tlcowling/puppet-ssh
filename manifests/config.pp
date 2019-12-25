# @summary Defines what is in the sshd_config, please note,this is using a restricted cipher, kexalgorithms and macs list and so consequently is less compatible with older ssh clients
#
# @example Simple class instantiation
#   class { 'ssh::config':
#     allow_agent_forwarding = false,
#   }
#
# @example Configuration using Hiera
#   ssh::config::compression: true
#   ssh::config::allow_users:
#     - fred
#     - jiminybob
#
# @param accept_env
#   Specifies what environment variables sent by the client will be copied into the session's environ(7).  See SendEnv in ssh_config(5) for how to configure the
#   client.  The TERM environment variable is always sent whenever the client requests a pseudo-terminal as it is required by the protocol.  Variables are specified
#   by name, which may contain the wildcard characters ‘*’ and ‘?’.  Multiple environment variables may be separated by whitespace or spread across multiple
#   AcceptEnv directives.  Be warned that some environment variables could be used to bypass restricted user environments.  For this reason, care should be taken in
#   the use of this directive.
# @param address_family
#   Specifies which address family should be used by sshd(8).  Valid arguments are any (the default), inet (use IPv4 only), or inet6 (use IPv6 only).
# @param allow_agent_forwarding
#   Specifies whether ssh-agent(1) forwarding is permitted.  The default is yes.  Note that disabling agent forwarding does not improve security unless users are
#   also denied shell access, as they can always install their own forwarders.
# @param allow_groups
#   This keyword can be followed by a list of group name patterns, separated by spaces.  If specified, login is allowed only for users whose primary group or sup‐
#   plementary group list matches one of the patterns.  Only group names are valid; a numerical group ID is not recognized.  By default, login is allowed for all
#   groups.  The allow/deny directives are processed in the following order: DenyUsers, AllowUsers, DenyGroups, and finally AllowGroups.
# @param allow_stream_local_forwarding
#   Specifies whether StreamLocal (Unix-domain socket) forwarding is permitted.  The available options are yes (the default) or all to allow StreamLocal forwarding,
#   no to prevent all StreamLocal forwarding, local to allow local (from the perspective of ssh(1)) forwarding only or remote to allow remote forwarding only.  Note
#   that disabling StreamLocal forwarding does not improve security unless users are also denied shell access, as they can always install their own forwarders.
# @param allow_tcp_forwarding
#   Specifies whether TCP forwarding is permitted.  The available options are yes (the default) or all to allow TCP forwarding, no to prevent all TCP forwarding,
#   local to allow local (from the perspective of ssh(1)) forwarding only or remote to allow remote forwarding only.  Note that disabling TCP forwarding does not
#   improve security unless users are also denied shell access, as they can always install their own forwarders.
# @param allow_users
#   This keyword can be followed by a list of user name patterns, separated by spaces.  If specified, login is allowed only for user names that match one of the
#   patterns.  Only user names are valid; a numerical user ID is not recognized.  By default, login is allowed for all users.  If the pattern takes the form
#   USER@HOST then USER and HOST are separately checked, restricting logins to particular users from particular hosts.  HOST criteria may additionally contain
#   addresses to match in CIDR address/masklen format.  The allow/deny directives are processed in the following order: DenyUsers, AllowUsers, DenyGroups, and
#   finally AllowGroups.
# @param banner  
#   The contents of the specified file are sent to the remote user before authentication is allowed.  If the argument is none then no banner is displayed.  By
#   default, no banner is displayed.
# @param challenge_response_authentication
#   Specifies whether challenge-response authentication is allowed (e.g. via PAM).  The default is yes.
# @param chroot_directory
#   Specifies the pathname of a directory to chroot(2) to after authentication.  At session startup sshd(8) checks that all components of the pathname are root-
#   owned directories which are not writable by any other user or group.  After the chroot, sshd(8) changes the working directory to the user's home directory.
#   Arguments to ChrootDirectory accept the tokens described in the TOKENS section.
#   The ChrootDirectory must contain the necessary files and directories to support the user's session.  For an interactive session this requires at least a shell,
#   typically sh(1), and basic /dev nodes such as null(4), zero(4), stdin(4), stdout(4), stderr(4), and tty(4) devices.  For file transfer sessions using SFTP no
#   additional configuration of the environment is necessary if the in-process sftp-server is used, though sessions which use logging may require /dev/log inside
#   the chroot directory on some operating systems (see sftp-server(8) for details).
#   For safety, it is very important that the directory hierarchy be prevented from modification by other processes on the system (especially those outside the
#   jail).  Misconfiguration can lead to unsafe environments which sshd(8) cannot detect.
# @param ciphers
#   Specifies the ciphers allowed.  Multiple ciphers must be comma-separated.  If the specified value begins with a ‘+’ character, then the specified ciphers will
#   be appended to the default set instead of replacing them.  If the specified value begins with a ‘-’ character, then the specified ciphers (including wildcards)
#   will be removed from the default set instead of replacing them.
#   The list of available ciphers may also be obtained using "ssh -Q cipher".
# @param client_alive_count_max
#    Sets the number of client alive messages which may be sent without sshd(8) receiving any messages back from the client.  If this threshold is reached while
#    client alive messages are being sent, sshd will disconnect the client, terminating the session.  It is important to note that the use of client alive messages
#    is very different from TCPKeepAlive.  The client alive messages are sent through the encrypted channel and therefore will not be spoofable.  The TCP keepalive
#    option enabled by TCPKeepAlive is spoofable.  The client alive mechanism is valuable when the client or server depend on knowing when a connection has become
#    inactive.
# @param client_alive_count_interval
#   Sets a timeout interval in seconds after which if no data has been received from the client, sshd(8) will send a message through the encrypted channel to
#   request a response from the client.  The default is 0, indicating that these messages will not be sent to the client.
# @param compression
#   Specifies whether compression is enabled after the user has authenticated successfully.  The argument must be yes, delayed (a legacy synonym for yes) or no.
# @param debian_banner
#   Specifies whether the distribution-specified extra version suffix is included during initial protocol handshake.
# @param deny_groups
#   This keyword can be followed by a list of group name patterns, separated by spaces.  Login is disallowed for users whose primary group or supplementary group
#   list matches one of the patterns.  Only group names are valid; a numerical group ID is not recognized.  By default, login is allowed for all groups.  The
#   allow/deny directives are processed in the following order: DenyUsers, AllowUsers, DenyGroups, and finally AllowGroups.
# @param deny_users
#   This keyword can be followed by a list of user name patterns, separated by spaces.  Login is disallowed for user names that match one of the patterns.  Only
#   user names are valid; a numerical user ID is not recognized.  By default, login is allowed for all users.  If the pattern takes the form USER@HOST then USER and
#   HOST are separately checked, restricting logins to particular users from particular hosts.  HOST criteria may additionally contain addresses to match in CIDR
#   address/masklen format.  The allow/deny directives are processed in the following order: DenyUsers, AllowUsers, DenyGroups, and finally AllowGroups.#
# @param disable_forwarding
#   Disables all forwarding features, including X11, ssh-agent(1), TCP and StreamLocal.  This option overrides all other forwarding-related options and may simplify
#   restricted configurations.
# @param fingerprint_hash
#   Specifies the hash algorithm used when logging key fingerprints.  Valid options are: md5 and sha256.  The default is sha256.
# @param ignore_rhosts
#   Specifies that .rhosts and .shosts files will not be used in HostbasedAuthentication.
#   /etc/hosts.equiv and /etc/ssh/shosts.equiv are still used.
# @param gssapi_authentication
#   Specifies whether user authentication based on GSSAPI is allowed.
# @param kex_algorithms
#   Specifies the available KEX (Key Exchange) algorithms.  Multiple algorithms must be comma-separated.  Alternately if the specified value begins with a ‘+’ char‐
#   acter, then the specified methods will be appended to the default set instead of replacing them.  If the specified value begins with a ‘-’ character, then the
#   specified methods (including wildcards) will be removed from the default set instead of replacing them.
#   The list of available key exchange algorithms may also be obtained using "ssh -Q kex".
# @param listen_addresses
#   Specifies the local addresses sshd(8) should listen on.  The following forms may be used:
#     ListenAddress host|IPv4_addr|IPv6_addr
#     ListenAddress host|IPv4_addr:port
#     ListenAddress [host|IPv6_addr]:port
#   If port is not specified, sshd will listen on the address and all Port options specified.  The default is to listen on all local addresses.  Multiple
#   ListenAddress options are permitted.
# @param login_grace_time
#   The server disconnects after this time if the user has not successfully logged in.  If the value is 0, there is no time limit.  The default is 120 seconds.
# @param log_level
#   Gives the verbosity level that is used when logging messages from sshd(8).  The possible values are: QUIET, FATAL, ERROR, INFO, VERBOSE, DEBUG, DEBUG1, DEBUG2,
#   and DEBUG3.  The default is INFO.  DEBUG and DEBUG1 are equivalent.  DEBUG2 and DEBUG3 each specify higher levels of debugging output.  Logging with a DEBUG
#   level violates the privacy of users and is not recommended.
# @param macs
#   Specifies the available MAC (message authentication code) algorithms.  The MAC algorithm is used for data integrity protection.  Multiple algorithms must be
#   comma-separated.  If the specified value begins with a ‘+’ character, then the specified algorithms will be appended to the default set instead of replacing
#   them.  If the specified value begins with a ‘-’ character, then the specified algorithms (including wildcards) will be removed from the default set instead of
#   replacing them.
#   The algorithms that contain "-etm" calculate the MAC after encryption (encrypt-then-mac).  These are considered safer and their use recommended.  The supported
#   MACs are:
#      hmac-md5
#      hmac-md5-96
#      hmac-sha1
#      hmac-sha1-96
#      hmac-sha2-256
#      hmac-sha2-512
#      umac-64@openssh.com
#      umac-128@openssh.com
#      hmac-md5-etm@openssh.com
#      hmac-md5-96-etm@openssh.com
#      hmac-sha1-etm@openssh.com
#      hmac-sha1-96-etm@openssh.com
#      hmac-sha2-256-etm@openssh.com
#      hmac-sha2-512-etm@openssh.com
#      umac-64-etm@openssh.com
#      umac-128-etm@openssh.com
#   The list of available MAC algorithms may also be obtained using "ssh -Q mac".
# @param gssapi_cleanup_credentials
#   Specifies whether to automatically destroy the user's credentials cache on logout.
# @param max_auth_tries
#   Specifies the maximum number of authentication attempts permitted per connection.  Once the number of failures reaches half this value, additional failures are
#   logged.
# @param max_sessions
#   Specifies the maximum number of open shell, login or subsystem (e.g. sftp) sessions permitted per network connection.  Multiple sessions may be established by
#   clients that support connection multiplexing.  Setting MaxSessions to 1 will effectively disable session multiplexing, whereas setting it to 0 will prevent all
#   shell, login and subsystem sessions while still permitting forwarding.
# @param max_startups
#   Specifies the maximum number of concurrent unauthenticated connections to the SSH daemon.  Additional connections will be dropped until authentication succeeds
#   or the LoginGraceTime expires for a connection.  The default is 10:30:100.
#   Alternatively, random early drop can be enabled by specifying the three colon separated values start:rate:full (e.g. "10:30:60").  sshd(8) will refuse connec‐
#   tion attempts with a probability of rate/100 (30%) if there are currently start (10) unauthenticated connections.  The probability increases linearly and all
#   connection attempts are refused if the number of unauthenticated connections reaches full (60).
# @param password_authentication
#   Specifies whether password authentication is allowed.
# @param permit_empty_passwords
#   When password authentication is allowed, it specifies whether the server allows login to accounts with empty password strings.
# @param permit_open
#   Specifies the destinations to which TCP port forwarding is permitted.  The forwarding specification must be one of the following forms:
#      PermitOpen host:port
#      PermitOpen IPv4_addr:port
#      PermitOpen [IPv6_addr]:port
#   Multiple forwards may be specified by separating them with whitespace.  An argument of any can be used to remove all restrictions and permit any forwarding
#   requests.  An argument of none can be used to prohibit all forwarding requests.  The wildcard ‘*’ can be used for host or port to allow all hosts or ports,
#   respectively.  By default all port forwarding requests are permitted.
# @param permit_root_login
#   Specifies whether root can log in using ssh(1).  The argument must be yes, prohibit-password, without-password, forced-commands-only, or no.  The default is
#   prohibit-password.
#   If this option is set to prohibit-password or without-password, password and keyboard-interactive authentication are disabled for root.
#   If this option is set to forced-commands-only, root login with public key authentication will be allowed, but only if the command option has been specified
#   (which may be useful for taking remote backups even if root login is normally not allowed).  All other authentication methods are disabled for root.
#   If this option is set to no, root is not allowed to log in.
# @param permit_tty
#    Specifies whether pty(4) allocation is permitted.  The default is yes.
# @param permit_tunnel
#    Specifies whether tun(4) device forwarding is allowed.  The argument must be yes, point-to-point (layer 3), ethernet (layer 2), or no.  Specifying yes permits
#    both point-to-point and ethernet.  The default is no.
#
#    Independent of this setting, the permissions of the selected tun(4) device must allow access to the user.
# @param port
#   Specifies the port number that sshd(8) listens on.  The default is 22.  Multiple options of this type are permitted.  See also ListenAddress.
# @param print_motd
#   Specifies whether sshd(8) should print /etc/motd when a user logs in interactively.  (On some systems it is also printed by the shell, /etc/profile, or equiva‐
#   lent.)
# @param tcp_keepalive
#   Specifies whether the system should send TCP keepalive messages to the other side.  If they are sent, death of the connection or crash of one of the machines
#   will be properly noticed.  However, this means that connections will die if the route is down temporarily, and some people find it annoying.  On the other hand,
#   if TCP keepalives are not sent, sessions may hang indefinitely on the server, leaving "ghost" users and consuming server resources.
#   The default is yes (to send TCP keepalive messages), and the server will notice if the network goes down or the client host crashes.  This avoids infinitely
#   hanging sessions.
#   To disable TCP keepalive messages, the value should be set to no.
#   This option was formerly called KeepAlive.
# @param pubkey_authentication
#    Specifies whether public key authentication is allowed.
# @param use_dns
#   Specifies whether sshd(8) should look up the remote host name, and to check that the resolved host name for the remote IP address maps back to the very same IP
#   address.
#   If this option is set to no (the default) then only addresses and not host names may be used in ~/.ssh/authorized_keys from and sshd_config Match Host direc‐
#   tives.
# @param use_pam  Enables the Pluggable Authentication Module interface.  If set to yes this will enable PAM authentication using ChallengeResponseAuthentication and
#   PasswordAuthentication in addition to PAM account and session module processing for all authentication types.
#   Because PAM challenge-response authentication usually serves an equivalent role to password authentication, you should disable either PasswordAuthentication or
#   ChallengeResponseAuthentication.
#   If UsePAM is enabled, you will not be able to run sshd(8) as a non-root user.
# @param strict_modes
#   Specifies whether sshd(8) should check file modes and ownership of the user's files and home directory before accepting login.  This is normally desirable
#   because novices sometimes accidentally leave their directory or files world-writable.  The default is yes.  Note that this does not apply to ChrootDirectory,
#   whose permissions and ownership are checked unconditionally.
# @param x11_forwarding
#   Specifies whether X11 forwarding is permitted.  The argument must be yes or no.  The default is no.
#   When X11 forwarding is enabled, there may be additional exposure to the server and to client displays if the sshd(8) proxy display is configured to listen on
#   the wildcard address (see X11UseLocalhost), though this is not the default.  Additionally, the authentication spoofing and authentication data verification and
#   substitution occur on the client side.  The security risk of using X11 forwarding is that the client's X11 display server may be exposed to attack when the SSH
#   client requests forwarding (see the warnings for ForwardX11 in ssh_config(5)).  A system administrator may have a stance in which they want to protect clients
#   that may expose themselves to attack by unwittingly requesting X11 forwarding, which can warrant a no setting.
#   Note that disabling X11 forwarding does not prevent users from forwarding X11 traffic, as users can always install their own forwarders.
# @param x11_use_localhost
#   Specifies whether sshd(8) should bind the X11 forwarding server to the loopback address or to the wildcard address.  By default, sshd binds the forwarding
#   server to the loopback address and sets the hostname part of the DISPLAY environment variable to localhost.  This prevents remote hosts from connecting to the
#   proxy display.  However, some older X11 clients may not function with this configuration.  X11UseLocalhost may be set to no to specify that the forwarding
#   server should be bound to the wildcard address.  The argument must be yes or no.  The default is yes.
class ssh::config (
  Array[Numeric] $port = $::ssh::params::port,
  Numeric $protocol = $::ssh::params::protocol,
  Array[String] $host_keys = $::ssh::params::host_keys,
  Array[String] $listen_addresses = $::ssh::params::listen_addresses,
  Enum['any','ipv4','ipv6'] $address_family = $::ssh::params::address_family,
  String $syslog_facility = $::ssh::params::syslog_facility,
  Enum['INFO','VERBOSE',"DEBUG',"] $log_level = $::ssh::params::log_level,
  Numeric $login_grace_time = $::ssh::params::login_grace_time,
  Enum['yes','no','without-password'] $permit_root_login = $::ssh::params::permit_root_login,
  Boolean $strict_modes = $::ssh::params::strict_modes,
  Boolean $pubkey_authentication = $::ssh::params::pubkey_authentication,
  Boolean $rsa_authentication = $::ssh::params::rsa_authentication,
  String $authorized_keys_file = $::ssh::params::authorized_keys_file,
  Boolean $password_authentication = $::ssh::params::password_authentication,
  Boolean $ignore_user_known_hosts = $::ssh::params::ignore_user_known_hosts,
  Boolean $permit_empty_passwords = $::ssh::params::permit_empty_passwords,
  Boolean $permit_tty = $::ssh::params::permit_tty,
  Array[String] $permit_open = $::ssh::params::permit_open,
  Boolean $challenge_response_authentication = $::ssh::params::challenge_response_authentication,
  Boolean $gssapi_authentication = $::ssh::params::gssapi_authentication,
  Boolean $gssapi_cleanup_credentials = $::ssh::params::gssapi_cleanup_credentials,
  Boolean $use_dns = $::ssh::params::use_dns,
  Boolean $use_pam = $::ssh::params::use_pam,
  Boolean $allow_agent_forwarding = $::ssh::params::allow_agent_forwarding,
  Boolean $allow_tcp_forwarding = $::ssh::params::allow_tcp_forwarding,
  Boolean $x11_forwarding = $::ssh::params::x11_forwarding,
  Boolean $x11_use_localhost = $::ssh::params::x11_use_localhost,
  Boolean $permit_user_environment = $::ssh::params::permit_user_environment,
  Boolean $print_motd = $::ssh::params::print_motd,
  Boolean $tcp_keepalive = $::ssh::params::tcp_keepalive,
  Boolean $compression = $::ssh::params::compression,
  Boolean $allow_stream_local_forwarding = $::ssh::params::allow_stream_local_forwarding,
  Numeric $client_alive_count_interval = $::ssh::params::client_alive_count_interval,
  Numeric $client_alive_count_max = $::ssh::params::client_alive_count_max,
  String $chroot_directory = $::ssh::params::chroot_directory,
  Boolean $permit_tunnel = $::ssh::params::permit_tunnel,
  Numeric $max_auth_tries = $::ssh::params::max_auth_tries,
  Numeric $max_sessions = $::ssh::params::max_sessions,
  String $banner = $::ssh::params::banner,
  Array[String] $kex_algorithms = $::ssh::params::kex_algorithms,
  Array[String] $ciphers = $::ssh::params::ciphers,
  Array[String] $macs = $::ssh::params::macs,
  Array[String] $allow_users = [],
  Array[String] $allow_groups = [],
  Array[String] $deny_users = [],
  Array[String] $deny_groups = [],
  Array[String] $authentication_methods = [],
  Array[String] $accept_env = $::ssh::params::accept_env,
  Boolean $debian_banner = $::ssh::params::debian_banner,
  Enum['sha256','md5'] $fingerprint_hash = $::ssh::params::fingerprint_hash,
  Boolean $disable_forwarding = $::ssh::params::disable_forwarding,
  Boolean $ignore_rhosts = $::ssh::params::ignore_rhosts,
){
  file { '/etc/ssh/sshd_config':
    ensure  => present,
    mode    => '0640',
    owner   => 'root',
    group   => 'root',
    notify  => Exec['sshd config test'],
    content => template('ssh/sshd_config.erb'),
  }

  exec { 'sshd config test':
    command => 'sshd -T',
    path    => ['/usr/sbin', '/usr/bin',],
  }
}
