#!/usr/bin/env python3
"""
Generate slug-icon.ico (multi-size Windows icon) from a Python-drawn PNG.
Sizes: 16, 24, 32, 48, 64, 128, 256 px.
No external dependencies needed (uses only stdlib + ctypes for BMP).
"""
import struct, zlib, io, os

def make_png(size):
    """Create a minimal cyan-gradient 'slug' PNG in pure Python (no Pillow)."""
    img_w, img_h = size, size

    # Build RGBA pixel array
    pixels = []
    for y in range(img_h):
        row = []
        for x in range(img_w):
            # Background: dark transparent
            # Draw rounded rectangle badge
            cx, cy = img_w / 2, img_h / 2
            rx, ry = img_w * 0.45, img_h * 0.45
            # ellipse check for rounded bg
            dx, dy = (x - cx) / rx, (y - cy) / ry
            in_badge = (dx*dx + dy*dy) <= 1.0

            if in_badge:
                # gradient: cyan (#00F2FE) -> blue (#4FACFE) -> green (#00FFA3)
                t = x / max(img_w - 1, 1)
                if t < 0.45:
                    s = t / 0.45
                    r = int(0   + s * 79)
                    g = int(242 - s * 155)
                    b = int(254 - s * 0)
                else:
                    s = (t - 0.45) / 0.55
                    r = int(79  - s * 79)
                    g = int(172 - s * 9)
                    b = int(254 - s * 91)
                a = 255
            else:
                r, g, b, a = 0, 0, 0, 0

            row.append((r, g, b, a))
        pixels.append(row)

    # Render "s" glyph as a simple pixel art letter at small sizes
    # For sizes >= 32 draw a simple "S" shape using block pixels
    if size >= 32:
        char_w = max(1, size // 8)
        char_h = max(1, size // 8)
        cx = size // 2
        cy = size // 2
        # S-shape: top bar, mid bar, bot bar + left-top, right-bot verticals
        bars = []
        s = size // 4
        thickness = max(1, size // 16)
        # top horizontal
        bars.append((cx - s, cy - s, 2*s, thickness, 10, 20, 20))
        # mid horizontal
        bars.append((cx - s, cy - thickness//2, 2*s, thickness, 10, 20, 20))
        # bot horizontal
        bars.append((cx - s, cy + s - thickness, 2*s, thickness, 10, 20, 20))
        # left side top
        bars.append((cx - s, cy - s, thickness, s + thickness, 10, 20, 20))
        # right side bottom
        bars.append((cx + s - thickness, cy - thickness//2, thickness, s + thickness, 10, 20, 20))

        for bx, by, bw, bh, dr, dg, db in bars:
            for py in range(max(0, by), min(size, by + bh)):
                for px in range(max(0, bx), min(size, bx + bw)):
                    r, g, b, a = pixels[py][px]
                    if a > 0:
                        pixels[py][px] = (
                            max(0, r - dr),
                            max(0, g - dg),
                            max(0, b - db),
                            a
                        )

    # Build PNG bytes
    def make_chunk(ctype, data):
        c = ctype if isinstance(ctype, bytes) else ctype.encode()
        crc = zlib.crc32(c + data) & 0xFFFFFFFF
        return struct.pack('>I', len(data)) + c + data + struct.pack('>I', crc)

    png_sig = b'\x89PNG\r\n\x1a\n'
    ihdr = make_chunk('IHDR', struct.pack('>IIBBBBB', img_w, img_h, 8, 2, 0, 0, 0))
    # RGB only (drop alpha for ICO compat), but use RGBA
    ihdr = make_chunk('IHDR', struct.pack('>IIBBBBB', img_w, img_h, 8, 6, 0, 0, 0))

    raw_rows = b''
    for row in pixels:
        raw_rows += b'\x00'  # filter type None
        for (r, g, b, a) in row:
            raw_rows += bytes([r, g, b, a])

    compressed = zlib.compress(raw_rows, 9)
    idat = make_chunk('IDAT', compressed)
    iend = make_chunk('IEND', b'')

    return png_sig + ihdr + idat + iend


def build_ico(sizes=(256, 128, 64, 48, 32, 24, 16)):
    """Build a Windows .ico file containing multiple PNG images."""
    images = {}
    for s in sizes:
        images[s] = make_png(s)

    # ICO header
    num = len(sizes)
    header = struct.pack('<HHH', 0, 1, num)  # reserved, type=1 (ICO), count

    # Each directory entry is 16 bytes
    # image data starts after header (6 bytes) + directory (num * 16 bytes)
    offset = 6 + num * 16

    dir_entries = b''
    image_data = b''

    for s in sizes:
        img = images[s]
        img_len = len(img)
        w = s if s < 256 else 0   # 0 means 256 for ICO format
        h = s if s < 256 else 0
        dir_entries += struct.pack('<BBBBHHII',
            w,         # width
            h,         # height
            0,         # color count (0 for PNG)
            0,         # reserved
            1,         # color planes
            32,        # bits per pixel
            img_len,   # size of image data
            offset     # offset of image data
        )
        offset += img_len
        image_data += img

    return header + dir_entries + image_data


if __name__ == '__main__':
    out_path = os.path.join(os.path.dirname(__file__), '..', 'assets', 'slug-icon.ico')
    out_path = os.path.normpath(out_path)
    ico_bytes = build_ico()
    with open(out_path, 'wb') as f:
        f.write(ico_bytes)
    print(f'[+] Generated {out_path} ({len(ico_bytes)} bytes)')
