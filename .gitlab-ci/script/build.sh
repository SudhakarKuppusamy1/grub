#!/bin/bash

set -eu -o pipefail

PATH="$CROSS_C/ia64-linux/bin:$CROSS_C/loongarch64-linux/bin:$CROSS_C/riscv32-linux/bin:$PATH"
i="${TARGET}"
j="${PLATFORM}"

if [ "$j" = efi ] && [ "$i" != ia64-linux ] && [ "$i" != loongarch64-linux ] && [ "$i" != riscv64-linux-gnu ]; then
  ./configure --target="$i" --with-platform="$j" --enable-stack-protector --enable-grub-mkfont --prefix="$(pwd)/grub-dist"
else
  ./configure --target="$i" --with-platform="$j" --enable-grub-mkfont --prefix="$(pwd)/grub-dist"
fi

make --quiet install
make --quiet html
make --quiet pdf
