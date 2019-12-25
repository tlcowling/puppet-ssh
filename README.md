# ssh [![Documentation](https://img.shields.io/badge/docs-green.svg)](https://tlcowling.github.io/puppet-ssh/)

https://tlcowling.github.io/puppet-ssh/

1. [Description](#description)
2. [Setup - The basics of getting started with ssh](#setup)
    * [What ssh affects](#what-ssh-affects)
    * [Setup requirements](#setup-requirements)
    * [Beginning with ssh](#beginning-with-ssh)
3. [Usage - Configuration options and additional functionality](#usage)
4. [Limitations - OS compatibility, etc.](#limitations)
5. [Development - Guide for contributing to the module](#development)

## Description

Puppet module to configure OpenSSH on Linux.  Defaults to using a hardened configuration

I originally tried a whole bunch of puppet forge modules instead of
doing this but I couldn't get them to satisfy these requirements

- simple to compose module for masterless puppet using librarian-puppet
- fully configurable with hiera
- quick to run a puppet apply

I could not find a version of the ssh modules on puppet forge that
satisfied all the verison requirements of the other modules I was using
.

Additionally there were a number of modules that did seem to work but
did not allow full configuration in hiera.

Finally I got annoyed with all the various deprecation and warning messages
and realised that all I want for this module is a simple yet comprehensive
package/file/service setup with minimal dependencies.  Consequently, this
module uses only hiera and is very quick to apply.

I used PDK to generate this, hence the level of faff that is here


## Usage

Include usage examples for common use cases in the **Usage** section. Show your users how to use your module to solve problems, and be sure to include code examples. Include three to five examples of the most important or common tasks a user can accomplish with your module. Show users how to accomplish more complex tasks that involve different types, classes, and functions working in tandem.

## Reference

This section is deprecated. Instead, add reference information to your code as Puppet Strings comments, and then use Strings to generate a REFERENCE.md in your module. For details on how to add code comments and generate documentation with Strings, see the Puppet Strings [documentation](https://puppet.com/docs/puppet/latest/puppet_strings.html) and [style guide](https://puppet.com/docs/puppet/latest/puppet_strings_style.html)

If you aren't ready to use Strings yet, manually create a REFERENCE.md in the root of your module directory and list out each of your module's classes, defined types, facts, functions, Puppet tasks, task plans, and resource types and providers, along with the parameters for each.

For each element (class, defined type, function, and so on), list:

  * The data type, if applicable.
  * A description of what the element does.
  * Valid values, if the data type doesn't make it obvious.
  * Default value, if any.

## Development

In the Development section, tell other users the ground rules for contributing to your project and how they should submit their work.
