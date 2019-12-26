# @summary This class is meant to be called from ssh.  It ensure the service is running.
#
class ssh::service {
  service { $::ssh::service_name:
    ensure     => running,
    enable     => true,
    hasstatus  => true,
    hasrestart => true,
  }
}