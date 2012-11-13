Pinba module for nginx
======================

What
----
This is a Pinba module for nginx. It sends statistics packets by UDP that are received and processed by Pinba server to be accessible through MySQL interface.
See <http://pinba.org> for more details on how Pinba works.

Why
---
Because PHP stats are simply not enough and we want to see some more info directly from nginx servers. HTTP status codes stats were among the main reasons, but there is a lot more data than that. And more data means more nice graphs, yay!

Pre-requisites
--------------
nginx sources, C compiler.

Installation
------------
Add this to your nginx configure line:  

`--add-module=/path/to/ngx_http_pinba_module.git/`  

and then do `make install`.

Configuration options
---------------------
All configuration options must be added to the `http {}` section of the config file,
but you can always modify them in location/server sections.

`pinba_enable` - on/off.
The module is disabled by default.

`pinba_server` - the adress of Pinba server.  
Should be a valid `host:port` or `ip_address:port` combination.

`pinba_ignore_codes` - a list of HTTP status codes.  
Can be comma separated list or comma separated ranges of codes or both.  
No data packet will be sent if a request is finished with a final status from the list.

Example:  
`pinba_ignore_codes 200-399,499;`

Make sure there are no spaces between the values, though.

`pinba_buffer_size` - integer number.  
In general case you don't need this option.  
And to use it you'll have to upgrade Pinba server to the latest version first.  
That said, you might want to prevent nginx overloading your network by sending tons of packets, especially if you have a heavy loaded server. So the module can keep the data in the buffer and will send it only when there is no free space left the buffer. You'll have to tweak this value yourself, I can only say that Pinba packet size depends mostly on the URLs that are requested and in general case is less than 100 bytes.

`$pinba_request_uri` - variable.
Use this variable to specify custom script name value, the module always checks if this variable is defined and if it is, uses it.
The default value is nginx `$request_uri` variable without its GET parameters.

