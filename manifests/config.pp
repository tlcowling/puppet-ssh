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
# @param client_alive_interval
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
# @param host_based_uses_name_from_packet_only
#   Specifies whether or not the server will attempt to perform a reverse name lookup when matching the name in the ~/.shosts, ~/.rhosts, and /etc/hosts.equiv files
#   during HostbasedAuthentication.  A setting of yes means that sshd(8) uses the name supplied by the client rather than attempting to resolve the name from the
#   TCP connection itself.  The default is no.
# @param host_certificates
#   Specifies a file containing a public host certificate.  The certificate's public key must match a private host key already specified by HostKey.  The default
#   behaviour of sshd(8) is not to load any certificates.
# @param host_keys
#   Specifies a list of files containing a private host key used by SSH.  The defaults are /etc/ssh/ssh_host_rsa_key, /etc/ssh/ssh_host_ecdsa_key and
#   /etc/ssh/ssh_host_ed25519_key.
#   Note that sshd(8) will refuse to use a file if it is group/world-accessible and that the HostKeyAlgorithms option restricts which of the keys are actually used
#   by sshd(8).
#   It is possible to have multiple host key files.  It is also possible to specify public host key files instead.  In this case operations on the private key will
#   be delegated to an ssh-agent(1).
# @param host_key_agent
#   Identifies the UNIX-domain socket used to communicate with an agent that has access to the private host keys.  If the string "SSH_AUTH_SOCK" is specified, the
#   location of the socket will be read from the SSH_AUTH_SOCK environment variable.
# @param host_key_algorithms
#   Specifies the host key algorithms that the server offers.  The default for this option is:
#   ecdsa-sha2-nistp256-cert-v01@openssh.com,
#   ecdsa-sha2-nistp384-cert-v01@openssh.com,
#   ecdsa-sha2-nistp521-cert-v01@openssh.com,
#   ssh-ed25519-cert-v01@openssh.com,
#   ssh-rsa-cert-v01@openssh.com,
#   ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,
#   ssh-ed25519,ssh-rsa
#   The list of available key types may also be obtained using "ssh -Q key".
# @param ignore_user_known_hosts
#   Specifies whether sshd(8) should ignore the user's ~/.ssh/known_hosts during HostbasedAuthentication.  The default is no.
# @param ipqos
#   Specifies the IPv4 type-of-service or DSCP class for the connection.  Accepted values are af11, af12, af13, af21, af22, af23, af31, af32, af33, af41, af42,
#   af43, cs0, cs1, cs2, cs3, cs4, cs5, cs6, cs7, ef, lowdelay, throughput, reliability, a numeric value, or none to use the operating system default.  This option
#   may take one or two arguments, separated by whitespace.  If one argument is specified, it is used as the packet class unconditionally.  If two values are speci‐
#   fied, the first is automatically selected for interactive sessions and the second for non-interactive sessions.  The default is lowdelay for interactive ses‐
#   sions and throughput for non-interactive sessions.
# @param kbd_interactive_authentication
#   Specifies whether to allow keyboard-interactive authentication.  The argument to this keyword must be yes or no.  The default is to use whatever value
#   ChallengeResponseAuthentication is set to (by default yes).
# @param kerberos_authentication
#   Specifies whether the password provided by the user for PasswordAuthentication will be validated through the Kerberos KDC.  To use this option, the server needs
#   a Kerberos servtab which allows the verification of the KDC's identity.  The default is no.
# @param kerberos_authentication
#   If AFS is active and the user has a Kerberos 5 TGT, attempt to acquire an AFS token before accessing the user's home directory.  The default is no.
# @param kerberos_or_local_passwd
#   If password authentication through Kerberos fails then the password will be validated via any additional local mechanism such as /etc/passwd.  The default isyes.
# @param kerberos_ticket_cleanup
#   Specifies whether to automatically destroy the user's ticket cache file on logout.  The default is yes.
# @param permit_user_environment
#   Specifies whether ~/.ssh/environment and environment= options in ~/.ssh/authorized_keys are processed by sshd(8).  The default is no.  Enabling environment pro‐
#   cessing may enable users to bypass access restrictions in some configurations using mechanisms such as LD_PRELOAD.
# @param permit_user_rc
#   Specifies whether any ~/.ssh/rc file is executed.  The default is yes.
# @param pid_file
#   Specifies the file that contains the process ID of the SSH daemon, or none to not write one.  The default is /run/sshd.pid.
# @param print_last_log
#   Specifies whether sshd(8) should print the date and time of the last user login when a user logs in interactively.  The default is yes.
# @param pubkey_accepted_key_types
#   Specifies the key types that will be accepted for public key authentication as a comma-separated pattern list.  Alternately if the specified value begins with a
#   ‘+’ character, then the specified key types will be appended to the default set instead of replacing them.  If the specified value begins with a ‘-’ character,
#   then the specified key types (including wildcards) will be removed from the default set instead of replacing them.  The default for this option is
#   ecdsa-sha2-nistp256-cert-v01@openssh.com,
#   ecdsa-sha2-nistp384-cert-v01@openssh.com,
#   ecdsa-sha2-nistp521-cert-v01@openssh.com,
#   ssh-ed25519-cert-v01@openssh.com,
#   ssh-rsa-cert-v01@openssh.com,
#   ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,
#   ssh-ed25519,ssh-rsa
#   The list of available key types may also be obtained using "ssh -Q key".
# @param rekey_limit
#   Specifies the maximum amount of data that may be transmitted before the session key is renegotiated, optionally followed a maximum amount of time that may pass
#   before the session key is renegotiated.  The first argument is specified in bytes and may have a suffix of ‘K’, ‘M’, or ‘G’ to indicate Kilobytes, Megabytes, or
#   Gigabytes, respectively.  The default is between ‘1G’ and ‘4G’, depending on the cipher.  The optional second value is specified in seconds and may use any of
#   the units documented in the TIME FORMATS section.  The default value for RekeyLimit is default none, which means that rekeying is performed after the cipher's
#   default amount of data has been sent or received and no time based rekeying is done.
# @param revoked_keys
#   Specifies revoked public keys file, or none to not use one.  Keys listed in this file will be refused for public key authentication.  Note that if this file is
#   not readable, then public key authentication will be refused for all users.  Keys may be specified as a text file, listing one public key per line, or as an
#   OpenSSH Key Revocation List (KRL) as generated by ssh-keygen(1).  For more information on KRLs, see the KEY REVOCATION LISTS section in ssh-keygen(1).
# @param stream_local_bind_mask
#   Sets the octal file creation mode mask (umask) used when creating a Unix-domain socket file for local or remote port forwarding.  This option is only used for
#   port forwarding to a Unix-domain socket file.
#   The default value is 0177, which creates a Unix-domain socket file that is readable and writable only by the owner.  Note that not all operating systems honor
#   the file mode on Unix-domain socket files.
# @param stream_local_bind_unlink
#   Specifies whether to remove an existing Unix-domain socket file for local or remote port forwarding before creating a new one.  If the socket file already
#   exists and StreamLocalBindUnlink is not enabled, sshd will be unable to forward the port to the Unix-domain socket file.  This option is only used for port for‐
#   warding to a Unix-domain socket file.
#   The argument must be yes or no.  The default is no.
# @param subsystem
#   Configures an external subsystem (e.g. file transfer daemon).  Arguments should be a subsystem name and a command (with optional arguments) to execute upon sub‐
#   system request.
#   The command sftp-server implements the SFTP file transfer subsystem.
#   Alternately the name internal-sftp implements an in-process SFTP server.  This may simplify configurations using ChrootDirectory to force a different filesystem
#   root on clients.
# @param syslog_facility
#   Gives the facility code that is used when logging messages from sshd(8).  The possible values are: DAEMON, USER, AUTH, LOCAL0, LOCAL1, LOCAL2, LOCAL3, LOCAL4,
#   LOCAL5, LOCAL6, LOCAL7.  The default is AUTH.
# @param trusted_user_ca_keys
#   Specifies a file containing public keys of certificate authorities that are trusted to sign user certificates for authentication, or none to not use one.  Keys
#   are listed one per line; empty lines and comments starting with ‘#’ are allowed.  If a certificate is presented for authentication and has its signing CA key
#   listed in this file, then it may be used for authentication for any user listed in the certificate's principals list.  Note that certificates that lack a list
#   of principals will not be permitted for authentication using TrustedUserCAKeys.  For more details on certificates, see the CERTIFICATES section in
#   ssh-keygen(1).
# @param version_addendum
#   Optionally specifies additional text to append to the SSH protocol banner sent by the server upon connection.  The default is none.
# @param x11_display_offset
#   Specifies the first display number available for sshd(8)'s X11 forwarding.  This prevents sshd from interfering with real X11 servers.  The default is 10.
# @param xauth_location
#    Specifies the full pathname of the xauth(1) program, or none to not use one.  The default is /usr/bin/xauth.
# @param authentication_methods
#   Specifies the authentication methods that must be successfully completed for a user to be granted access.  This option must be followed by one or more comma-
#   separated lists of authentication method names, or by the single string any to indicate the default behaviour of accepting any single authentication method.  If
#   the default is overridden, then successful authentication requires completion of every method in at least one of these lists.
#   For example, "publickey,password publickey,keyboard-interactive" would require the user to complete public key authentication, followed by either password or
#   keyboard interactive authentication.  Only methods that are next in one or more lists are offered at each stage, so for this example it would not be possible to
#   attempt password or keyboard-interactive authentication before public key.
#   For keyboard interactive authentication it is also possible to restrict authentication to a specific device by appending a colon followed by the device identi‐
#   fier bsdauth, pam, or skey, depending on the server configuration.  For example, "keyboard-interactive:bsdauth" would restrict keyboard interactive authentica‐
#   tion to the bsdauth device.
#   If the publickey method is listed more than once, sshd(8) verifies that keys that have been used successfully are not reused for subsequent authentications.
#   For example, "publickey,publickey" requires successful authentication using two different public keys.
#   Note that each authentication method listed should also be explicitly enabled in the configuration.
#   The available authentication methods are: "gssapi-with-mic", "hostbased", "keyboard-interactive", "none" (used for access to password-less accounts when
#   PermitEmptyPassword is enabled), "password" and "publickey".
# @param authorized_keys_command
#   Specifies a program to be used to look up the user's public keys.  The program must be owned by root, not writable by group or others and specified by an abso‐
#   lute path.  Arguments to AuthorizedKeysCommand accept the tokens described in the TOKENS section.  If no arguments are specified then the username of the target
#   user is used.
#   The program should produce on standard output zero or more lines of authorized_keys output (see AUTHORIZED_KEYS in sshd(8)).  If a key supplied by
#   AuthorizedKeysCommand does not successfully authenticate and authorize the user then public key authentication continues using the usual AuthorizedKeysFile
#   files.  By default, no AuthorizedKeysCommand is run.
# @param authorized_keys_command_user
#   Specifies the user under whose account the AuthorizedKeysCommand is run.  It is recommended to use a dedicated user that has no other role on the host than run‐
#   ning authorized keys commands.  If AuthorizedKeysCommand is specified but AuthorizedKeysCommandUser is not, then sshd(8) will refuse to start.
# @param authorized_keys_file
#   Specifies the file that contains the public keys used for user authentication.  The format is described in the AUTHORIZED_KEYS FILE FORMAT section of sshd(8).
#   Arguments to AuthorizedKeysFile accept the tokens described in the TOKENS section.  After expansion, AuthorizedKeysFile is taken to be an absolute path or one
#   relative to the user's home directory.  Multiple files may be listed, separated by whitespace.  Alternately this option may be set to none to skip checking for
#   user keys in files.  The default is ".ssh/authorized_keys .ssh/authorized_keys2".
# @param authorized_principals_command
#   Specifies a program to be used to generate the list of allowed certificate principals as per AuthorizedPrincipalsFile.  The program must be owned by root, not
#   writable by group or others and specified by an absolute path.  Arguments to AuthorizedPrincipalsCommand accept the tokens described in the TOKENS section.  If
#   no arguments are specified then the username of the target user is used.
#   The program should produce on standard output zero or more lines of AuthorizedPrincipalsFile output.  If either AuthorizedPrincipalsCommand or
#   AuthorizedPrincipalsFile is specified, then certificates offered by the client for authentication must contain a principal that is listed.  By default, no
#   AuthorizedPrincipalsCommand is run.
# @param authorized_principals_command_user
#   Specifies the user under whose account the AuthorizedPrincipalsCommand is run.  It is recommended to use a dedicated user that has no other role on the host
#   than running authorized principals commands.  If AuthorizedPrincipalsCommand is specified but AuthorizedPrincipalsCommandUser is not, then sshd(8) will refuse
#   to start.
# @param authorized_principals_file
#   Specifies a file that lists principal names that are accepted for certificate authentication.  When using certificates signed by a key listed in
#   TrustedUserCAKeys, this file lists names, one of which must appear in the certificate for it to be accepted for authentication.  Names are listed one per line
#   preceded by key options (as described in AUTHORIZED_KEYS FILE FORMAT in sshd(8)).  Empty lines and comments starting with ‘#’ are ignored.
#   Arguments to AuthorizedPrincipalsFile accept the tokens described in the TOKENS section.  After expansion, AuthorizedPrincipalsFile is taken to be an absolute
#   path or one relative to the user's home directory.  The default is none, i.e. not to use a principals file – in this case, the username of the user must appear
#   in a certificate's principals list for it to be accepted.
#   Note that AuthorizedPrincipalsFile is only used when authentication proceeds using a CA listed in TrustedUserCAKeys and is not consulted for certification
#   authorities trusted via ~/.ssh/authorized_keys, though the principals= key option offers a similar facility (see sshd(8) for details).
# @param force_command
#   Forces the execution of the command specified by ForceCommand, ignoring any command supplied by the client and ~/.ssh/rc if present.  The command is invoked by
#   using the user's login shell with the -c option.  This applies to shell, command, or subsystem execution.  It is most useful inside a Match block.  The command
#   originally supplied by the client is available in the SSH_ORIGINAL_COMMAND environment variable.  Specifying a command of internal-sftp will force the use of an
#   in-process SFTP server that requires no support files when used with ChrootDirectory.  The default is none.
# @param gateway_ports
#   Specifies whether remote hosts are allowed to connect to ports forwarded for the client.  By default, sshd(8) binds remote port forwardings to the loopback
#   address.  This prevents other remote hosts from connecting to forwarded ports.  GatewayPorts can be used to specify that sshd should allow remote port forward‐
#   ings to bind to non-loopback addresses, thus allowing other hosts to connect.  The argument may be no to force remote port forwardings to be available to the
#   local host only, yes to force remote port forwardings to bind to the wildcard address, or clientspecified to allow the client to select the address to which the
#   forwarding is bound.  The default is no.
# @param gssapi_key_exchange
#   Specifies whether key exchange based on GSSAPI is allowed. GSSAPI key exchange doesn't rely on ssh keys to verify host identity.  The default is no.
# @param gssapi_strict_acceptor_check
#   Determines whether to be strict about the identity of the GSSAPI acceptor a client authenticates against.  If set to yes then the client must authenticate
#   against the host service on the current hostname.  If set to no then the client may authenticate against any service key stored in the machine's default store.
#   This facility is provided to assist with operation on multi homed machines.  The default is yes.
# @param gssapi_store_credentials_on_rekey
#   Controls whether the user's GSSAPI credentials should be updated following a successful connection rekeying. This option can be used to accepted renewed or
#   updated credentials from a compatible client. The default is no.
# @param host_based_accepted_key_types
#   Specifies the key types that will be accepted for hostbased authentication as a comma-separated pattern list.  Alternately if the specified value begins with a
#   ‘+’ character, then the specified key types will be appended to the default set instead of replacing them.  If the specified value begins with a ‘-’ character,
#   then the specified key types (including wildcards) will be removed from the default set instead of replacing them.  The default for this option is:
#   ecdsa-sha2-nistp256-cert-v01@openssh.com,
#   ecdsa-sha2-nistp384-cert-v01@openssh.com,
#   ecdsa-sha2-nistp521-cert-v01@openssh.com,
#   ssh-ed25519-cert-v01@openssh.com,
#   ssh-rsa-cert-v01@openssh.com,
#   ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,
#   ssh-ed25519,ssh-rsa
#   The list of available key types may also be obtained using "ssh -Q key".
# @param host_based_authentication
#   Specifies whether rhosts or /etc/hosts.equiv authentication together with successful public key client host authentication is allowed (host-based authentica‐
#   tion).  The default is no.
# @param config_comment
#   A message to print at the top of the sshd_config
class ssh::config (
  String $config_comment = $::ssh::params::config_coment,
  Array[Numeric] $port = $::ssh::params::port,
  Numeric $protocol = $::ssh::params::protocol,
  Array[String] $host_keys = $::ssh::params::host_keys,
  Array[String] $listen_addresses = $::ssh::params::listen_addresses,
  Enum['any','ipv4','ipv6'] $address_family = $::ssh::params::address_family,
  String $syslog_facility = $::ssh::params::syslog_facility,
  Enum['INFO','VERBOSE',"DEBUG',"] $log_level = $::ssh::params::log_level,
  Numeric $login_grace_time = $::ssh::params::login_grace_time,
  Variant[Boolean, Enum['yes','no','without-password']] $permit_root_login = $::ssh::params::permit_root_login,
  Boolean $strict_modes = $::ssh::params::strict_modes,
  Boolean $pubkey_authentication = $::ssh::params::pubkey_authentication,
  Array[String] $authorized_keys_file = $::ssh::params::authorized_keys_file,
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
  Numeric $client_alive_interval = $::ssh::params::client_alive_interval,
  Numeric $client_alive_count_max = $::ssh::params::client_alive_count_max,
  String $chroot_directory = $::ssh::params::chroot_directory,
  Boolean $permit_tunnel = $::ssh::params::permit_tunnel,
  Numeric $max_auth_tries = $::ssh::params::max_auth_tries,
  Numeric $max_sessions = $::ssh::params::max_sessions,
  String $banner = $::ssh::params::banner,
  Array[String] $kex_algorithms = $::ssh::params::kex_algorithms,
  Array[String] $ciphers = $::ssh::params::ciphers,
  Array[String] $macs = $::ssh::params::macs,
  Array[String] $allow_users = $::ssh::params::allow_users,
  Array[String] $allow_groups = [],
  Array[String] $deny_users = [],
  Array[String] $deny_groups = [],
  Array[String] $authentication_methods = [],
  Array[String] $accept_env = $::ssh::params::accept_env,
  Boolean $debian_banner = $::ssh::params::debian_banner,
  Enum['sha256','md5'] $fingerprint_hash = $::ssh::params::fingerprint_hash,
  Boolean $disable_forwarding = $::ssh::params::disable_forwarding,
  Boolean $ignore_rhosts = $::ssh::params::ignore_rhosts,
  String $max_startups = $::ssh::params::max_startups,
  String $authorized_keys_command = $::ssh::params::authorized_keys_command,
  String $authorized_keys_command_user = $::ssh::params::authorized_keys_command_user,
  String $authorized_principals_command =$::ssh::params::authorized_principals_command,
  String $force_command =$::ssh::params::force_command,
  Boolean $gateway_ports =$::ssh::params::gateway_ports,
  String $authorized_principals_command_user=$::ssh::params::authorized_principals_command_user,
  String $authorized_principals_file=$::ssh::params::authorized_principals_file,
  Boolean $gssapi_key_exchange=$::ssh::params::gssapi_key_exchange,
  Boolean $gssapi_store_credentials_on_rekey=$::ssh::params::gssapi_store_credentials_on_rekey,
  Boolean $gssapi_strict_acceptor_check=$::ssh::params::gssapi_strict_acceptor_check,
  Array[String] $host_based_accepted_key_types=$::ssh::params::host_based_accepted_key_types,
  Boolean $host_based_authentication=$::ssh::params::host_based_authentication,
  Array[String] $host_certificates=$::ssh::params::host_certificates,
  String $host_key_agent=$::ssh::params::host_key_agent,
  Array[String] $host_key_algorithms=$::ssh::params::host_key_algorithms,
  Array[
    Variant[
      Enum[
        'af11',
        'af12',
        'af13',
        'af21',
        'af22',
        'af23',
        'af31',
        'af32',
        'af33',
        'af41',
        'af42',
        'af43',
        'cs0',
        'cs1',
        'cs2',
        'cs3',
        'cs4',
        'cs5',
        'cs6',
        'cs7',
        'ef',
        'lowdelay',
        'throughput',
        'reliability',
      ],
      Numeric,
    ]
  ] $ipqos=$::ssh::params::ipqos,
  Boolean $host_based_uses_name_from_packet_only=$::ssh::params::host_based_uses_name_from_packet_only,
  Boolean $kbd_interactive_authentication=$::ssh::params::kbd_interactive_authentication,
  Boolean $kerberos_authentication=$::ssh::params::kerberos_authentication,
  Boolean $kerberos_get_afs_token=$::ssh::params::kerberos_get_afs_token,
  Boolean $kerberos_ticket_cleanup=$::ssh::params::kerberos_ticket_cleanup,
  Boolean $kerberos_or_local_passwd=$::ssh::params::kerberos_or_local_passwd,
  Boolean $permit_user_rc=$::ssh::params::permit_user_rc,
  String $pid_file = $::ssh::params::pid_file,
  Boolean $print_last_log=$::ssh::params::print_last_log,
  Array[String] $pubkey_accepted_key_types=$::ssh::params::pubkey_accepted_key_types,
  Array[String] $rekey_limit = $::ssh::params::rekey_limit,
  String $stream_local_bind_mask=$::ssh::params::stream_local_bind_mask,
  Boolean $stream_local_bind_unlink=$::ssh::params::stream_local_bind_unlink,
  Array[String] $subsystem=$::ssh::params::subsystem,
  String $trusted_user_ca_keys=$::ssh::params::trusted_user_ca_keys,
  Numeric $x11_display_offset=$::ssh::params::x11_display_offset,
  String $version_addendum=$::ssh::params::version_addendum,
  String $xauth_location=$::ssh::params::xauth_location,
  String $revoked_keys=$::ssh::params::revoked_keys,
) {
  file { '/etc/ssh/sshd_config':
    ensure  => present,
    mode    => '0600',
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
