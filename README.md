# sol

a tiny crypto library based on tweetnacl

## build

```bash
cd src
meson setup build
ninja -C build
```

this will build the library and the demo program.

## acknowledgements

this repository is heavily built on the following work:
+ [tweetnacl](https://tweetnacl.cr.yp.to/) minimalistic crypto library
+ [randombytes](https://github.com/dsprenkels/randombytes/tree/master) cross-platform randombytes implementation
