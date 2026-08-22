#!/usr/bin/env bash
# يبني بنية hicolor icon theme القياسية من أيقونات configs/branding/release/
# الاستخدام: stage-icons.sh <output-dir>
set -e

OUT="${1:?usage: stage-icons.sh <output-dir>}"
SRC_DIR="configs/branding/release"

declare -A SIZE_TO_FILE=(
  [16]="logo16.png"
  [22]="logo22.png"
  [24]="logo24.png"
  [32]="logo32.png"
  [48]="logo48.png"
  [64]="logo64.png"
  [128]="logo128.png"
  [256]="logo256.png"
  [512]="logo512.png"
  [1024]="logo1024.png"
)

rm -rf "$OUT"
mkdir -p "$OUT/hicolor"

for size in "${!SIZE_TO_FILE[@]}"; do
  src_file="$SRC_DIR/${SIZE_TO_FILE[$size]}"
  if [ -f "$src_file" ]; then
    dest_dir="$OUT/hicolor/${size}x${size}/apps"
    mkdir -p "$dest_dir"
    cp "$src_file" "$dest_dir/baz.png"
  else
    echo "تحذير: ملف الأيقونة غير موجود، تم تخطيه: $src_file" >&2
  fi
done

echo "تم تجهيز الأيقونات في: $OUT/hicolor"
find "$OUT/hicolor" -name "baz.png"
