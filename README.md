To package Nginx, clone this repo, clean it...
```
find debian/ -name '\.git*' -exec rm -rf {} \; &>/dev/null
rm -r debian/modules/nginx-upload-progress/test/
rm -r debian/modules/nginx-rtmp-module/test/
rm README.md
```
... and build it your favorite way
