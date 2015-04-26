Nginx Configuration Tool (ngx-conf)
===================================

A tool to help manage nginx confuration files.

Synopsis
--------

ngx-conf [-h] (-e | -d | -x | -l) [-f] [-r] [-v] FILE [FILES]

Description
-----------

Ngx-conf is a relatively simple tool to help manage Nginx configuration files.
It can be used to enable, disable, remove, and list configuration files. In the
case of configuration files in conf.d/\*.conf, it will handle renaming files to
an enabled/disabled state. In sites-{enabled,available}/\*, it will handle the
creation and removal of symbolic links.

**-h, --help**
  show a help message and exit
**-e, --enable**
  enable a configuration files
**-d, --disable**
  disable a configuration files
**-x, --remove**
  remove a configuration files; will prompt without -f
**-l, --list**
  list configuration files
**-f, --force**
  force change, even if doing so will destroy data
**-r, --reload**
  reload configuration after change
**-v, --verbose**
  show verbose output; default is quiet unless errors
**FILES**
  a list of configuration files to update

Using --force:

* In --remove will not prompt you to delete the file(s).
* In --enable will ignore conflicts.
* In --disable will ignore conflicts.
* In --disable will also delete files from sites-enabled.

Only one action (enable|disable|remove|list) can be performed at one time.

Examples
--------

ngx-conf -e site1 site2 site3
  enable "site{1,2,3}" configurations
ngx-conf -r -d site
  disable "site" configuration and reload nginx
ngx-conf -f -r -x site1 site2
  remove "site{1,2}" configurations without prompting and reload nginx

Configuration Files
-------------------

Three configuration files, if present, will be read. They will be read in the
following order; the next read file will always override the previous.

1. /etc/nginx/ngx.cfg
#. /etc/ngx.cfg
#. ngx.cfg

A sample configuration file with all options set to default::

    [DEFAULT]
    base_dir = /etc/nginx/
    conf_dir = conf.d/
    sites_en = sites-enabled/
    sites_dis = sites-available/
    conf_ext = .conf
    verbose = no
    reload = no
    force = no

Make sure that base_dir always has a trailing slash.

Any arguments given to the command will override configuration options.

Aliases
-------

If you're interested in any sort of a2{dis,en}{conf,mod,site}, you can create
some nice aliases. Examples:

* a2ensite -- alias ngxensite='ngx-conf -e'
* a2enconf -- alias ngxenconf='ngx-conf -e'
* a2dissite -- alias ngxdissite='ngx-conf -d'
* a2disconf -- alias ngxdisconf='ngx-conf -d'

Bugs
----

If you experience bugs, the best way to report them is to the upstream bug
tracker. This can be found at https://github.com/ngx/ngx-conf.

Authors
-------

The ngx-conf tool and manual page were written by Michael Lustfield <michael@lustfield.net>.
