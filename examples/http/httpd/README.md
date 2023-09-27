# Polytracker demo: Apache httpd 

## Quickstart
```
cd /path/to/polytracker/examples/http/httpd
./example_httpd.sh foo.txt
```
where `foo.txt` contains the raw text of an HTTP request.

## Notes on instrumentation
In order to enable polytracker instrumentation, we statically compile httpd, its dependencies, and its modules.

The default build includes the following statically compiled modules:
```
$ ./httpd -l
Compiled in modules:
  core.c
  mod_authz_core.c
  mod_so.c
  http_core.c
  prefork.c
  mod_unixd.c
```

In order to enable additional modules, modify the Dockerfile to include additional `--enable-MODULE=static`
or `--enable-modules-static=MODULE-LIST` directives during the final `./configure` command. 
(see the [httpd configruation documenation](https://httpd.apache.org/docs/2.4/programs/configure.html) for further details).
You may also need to modify the `httpd.conf` file in this directory (which is copied to `/usr/local/apache2/conf/httpd.conf` in the container), and potentially add module configuration files to 
the `/usr/local/apache2/conf/extra` directory.
