# @summary This class is called from ssh for install.
#
class ssh::install {
  package { $::ssh::package_name:
    ensure => present,
  }
}