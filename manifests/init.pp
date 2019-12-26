# @summary Installs and configures a hardened SSH server
#
# @param package_name
#   Override the name of the package if it is different from the default on your OS
# @param service_name
#   Override the name of the service if it is different from the default on your OS
class ssh (
  $package_name = $::ssh::params::package_name,
  $service_name = $::ssh::params::service_name,
) inherits ::ssh::params {

  # validate parameters here

  class { '::ssh::install': }
  -> class { '::ssh::config': }
  ~> class { '::ssh::service': }
  -> Class['::ssh']
}