# puppet-ssh [![Documentation](https://img.shields.io/badge/documentation-brightgreen.svg)](https://tlcowling.github.io/puppet-ssh/) [![Build status](https://ci.appveyor.com/api/projects/status/rwcioly3dv6nluy2?svg=true)](https://ci.appveyor.com/project/tlcowling/puppet-ssh)

## Overview

This is a puppet module to configure OpenSSH servers and clients on Linux with a
hardened ssh configuration.

### Goals
- simple to compose, minimum depdencies
- fully configurable with hiera
- quick to run a puppet apply
- no deprecation warnings with modern puppet

## Usage

### Configure entirely with Hiera
```puppet
# site.pp
include ssh
```

```yaml
# common.yaml
---
ssh::config::compression: true
```

### More
For usage and examples, see [Wiki](https://github.com/tlcowling/puppet-ssh/wiki)

## Development

- Use `rake` to run the test suite, see the build in appveyor.
- Create issues and/or PRs in github
- Any and all questions welcome - if it doesn't work for you, it's a bug!
