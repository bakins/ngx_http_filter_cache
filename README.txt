* Synopsis
filter_cache is very similar to the otehr caches in nginx.  It uses the same underlying core functionality.  However, it runs as a filter as late in the HTTP processing as possible.  This allows it to cache things such as the results of SSI and gzip.  It does not work on subrequests.  filter_cache returns 599 on a cache miss.  It returns 598 when the cache will be bypassed.  Note: when the cache is bypassed, it will not attempt to cache it by default.  This behavior is different from some othe rnginx caches.

* Directives
Most of the directoves are very similar to the proxy and fastcgi cache bultinto nginx.

** filter_cache
syntax: filter_cache zone|off
default: off
context: http, server, location
The directive specifies the area which actually is the share memory's name for caching. The same area can be used in several places. 

** filter_cache_path
syntax: filter_cache_path path [levels=m:n] keys_zone=name:size [inactive=time] [max_size=size]
default: none
context: http
This directive specifies path to the cache storage and other cache parameters. All data is stored in the files. The cache key and the name of cache file are calculated as MD5 sum of the proxied URL.
Level parameter sets number and width of the names of subdirectories used to store caching files. For example, with the directive like:
filter_cache_path  /data/nginx/cache  levels=1:2   keys_zone=one:10m;
the data will be stored in the following file:
/data/nginx/cache/c/29/b7f54b2df7773722d382f4809d65029c
Caching data is first written to the temporary file which is then moved to the final location in a cache directory. Starting from 0.8.9 it is possible to store temporary and cache files on different file systems, but it should be kept in mind that in such a case instead of cheap and atomic rename syscall a full file copy is performed. So it's better to use the same file system in both parameters of filter_temp_path and filter_cache_path directives.
In addition, all active keys and information about data are kept in the shared memory zone, which name and size are specified by the options of the key_zone parameter. In case this data haven't been accessed for the time, specified in the option of inactive parameter, it is wiped out from the memory. By default inactive period is set to 10 minutes.
To maintain the maximum size of the cache, which is set by max_size parameter, a special process cache manager periodically deletes old data from the cache. 

** filter_cache_methods
Which HTTP methods are allowed to be used when caching requests.
syntax: filter_cache_methods [GET HEAD POST];
default: filter_cache_methods GET HEAD;
context: main, http, location
This directive specifies which HTTP methods are allowed to be used when caching requests. Note that GET and HEAD are syntactic sugars, i.e., a mere convenience in terms of this directive configuration logic. They cannot be disabled even if you set:
filter_cache_methods  POST; # note that GET and HEAD are still enabled
Note: filter_cache will espond to HEAD requests that are in the cache, but will not cache a pure HEAD reuqest.  This is because of the way the filter stack works, even though HEAD is a valid option here it is not used.

** filter_cache_min_uses
syntax: filter_cache_min_uses n
default: filter_cache_min_uses 1
context: http, server, location
Directive specifies after how many requests to the same URL in will be cached.

** filter_cache_use_stale
syntax: filter_cache_use_stale updating|error|timeout|invalid_header|http_500
default: filter_cache_use_stale off
context: http, server, location
Determines whether or not Nginx will serve stale cached data in case of gateway event such as error, timeout etc. Note: only "updating" currently works.

** filter_cache_valid
syntax: filter_cache_valid [http_return_code [...]] time
default: none
context: http, server, location
Directive sets caching period for the specified http return codes. For example:
filter_cache_valid  200 302  10m;
filter_cache_valid  404      1m;
sets caching period of 10 minutes for return codes 200 and 302 and 1 minute for the 404 code.
In case only caching period is specified:
filter_cache_valid  5m;
the default behavior is to cache only replies with the codes 200, 301 and 302.
It's also possible to cache all the replies by specifying code "any":
filter_cache_valid  200 302 10m;
filter_cache_valid  301 1h;
filter_cache_valid  any 1m;

** filter_cache_disable
syntax: filter_cache_disable variable [...]
default: none
context: http, server, location
Specifies in what cases the cached responses will not be used, e.g.
  filter_cache_disable $cookie_nocache  $arg_nocache$arg_comment;
  filter_cache_disable $http_pragma     $http_authorization;
The expression is false if it is equal to the empty string or "0". For instance, in the above example, the cache will be bypassed if the cookie "nocache" is set in the request. 

** filter_temp_path
syntax: filter_temp_path path [level1 [level2 [level3]]]
default: filter_temp_path filter_temp
context: http, server, location
This directive sets the path where to store temporary files received from another server. It is possible to use up to 3 levels of subdirectories to create hashed storage. Level value specifies how many symbols will be used for hashing. For example, in the following configuration:
filter_temp_path  /spool/nginx/filter_temp 1 2;
Temporary file name may look like:
/spool/nginx/filter_temp/7/45/00000123457

** filter_cache_bypass
syntax: proxy_cache_bypass line [...];
default: off
context: http, server, location
The directive specifies the conditions under which the answer will not be taken from the cache. If at least one of a string variable is not empty and not equal to "0", the answer is not taken from the cache:
 filter_cache_bypass $ cookie_nocache $ arg_nocache $ arg_comment;
 filter_cache_bypass $ http_pragma $ http_authorization;
Can be used in conjunction with the directive filter_cache_disable. 

** filter_cache_disable
syntax: filter_cache_disable variable1 variable2 ...;
default: None
context: http, server, location
Specifies in what cases a cached response will not be used, e.g.
filter_cache_disable $cookie_nocache  $arg_nocache$arg_comment;
filter_cache_disable $http_pragma     $http_authorization;
The expression is false if it is equal to the empty string or "0". For instance, in the above example, the request will always go through to the back-end if the cookie "nocache" is set in the request.
Note that the response from the back-end is still eligible for caching. Thus one way of refreshing an item in the cache is sending a request with a header you pick yourself, e.g. "My-Secret-Header: 1", then having a proxy_no_cache line like:
filter_cache_disable $http_my_secret_header;

** filter_cache_grace
syntax: filter_cache_grace 60s;
default: None
context: http, server, location
Specifies the amount of time after an item has expired in cache and is
updating that it can be served.  Use with
filter_cache_use_stale_updating.  If not set, or set to 0, this is
disabled.

Copyright & License

/* 
 * Copyright (C) 2002-2011 Brian Akins
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
