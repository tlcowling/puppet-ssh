# Class: ssh
# ===========================
#
# Installs and configures a hardened SSH server
#
# Parameters
# ----------
#
# * `sample parameter`
#   Explanation of what this parameter affects and what it defaults to.
#   e.g. "Specify one or more upstream ntp servers as an array."
#
class ssh (
  $package_name = $::ssh::params::package_name,
  $service_name = $::ssh::params::service_name,
) inherits ::ssh::params {

  # validate parameters here

  class { '::ssh::install': } ->
  class { '::ssh::config': } ~>
  class { '::ssh::service': } ->
  Class['::ssh']
}