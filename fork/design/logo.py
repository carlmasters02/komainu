"""Komainu logo builder: pixel-art lions -> half-block text, + OpenCode-style wordmark, + PNG preview."""
import json, sys
from PIL import Image, ImageDraw

# Left guardian ("a", mouth open), facing right. '#' = filled pixel, 'o' = eye (hole), '.' = empty.
LION_A = """
.......#.#.#........
.#....#########.....
#.#..###########....
#..#.####oo######...
.#.#.#############..
..##.##########.....
..##.####.#.#.......
..##.##########.....
..##.###########....
...#.###########....
...##############...
..###############...
..########.####.#...
..########.####.#...
..##.#####.####.#...
.###.#####.####.##..
####################
####################
"""

LION_UN_MOUTH = [(6, 9), (6, 11), (6, 13), (6, 14)]

def grid(art):
    return [list(r) for r in art.strip("\n").split("\n")]

def close_mouth(g):
    # "un" lion: fill the open-mouth gap so the jaw is shut
    g = [r[:] for r in g]
    for y, x in LION_UN_MOUTH: g[y][x] = "#"
    return g

def mirror(g):
    return [r[::-1] for r in g]

def to_half_blocks(g):
    rows = []
    for y in range(0, len(g), 2):
        top, bot = g[y], g[y + 1] if y + 1 < len(g) else ["."] * len(g[y])
        line = ""
        for t, b in zip(top, bot):
            T, B = t == "#", b == "#"
            line += "█" if T and B else "▀" if T else "▄" if B else " "
        rows.append(line)
    return rows

# OpenCode-style letters: row0 = accent row, rows 1-3 = glyph. Markers: _ shadow fill, ^ ▀ on shadow, ~ shadow ▀
LETTERS = {
    "K": ["    ", "█ ▄▀", "█▀▄_", "▀~~▀"],
    "O": ["    ", "█▀▀█", "█__█", "▀▀▀▀"],
    "M": ["     ", "█▀▄▀█", "█_▀_█", "▀~~~▀"],
    "A": ["    ", "█▀▀█", "█▀▀█", "▀~~▀"],
    "I": [" ", "█", "█", "▀"],
    "N": ["    ", "█▀▀▄", "█__█", "▀~~▀"],
    "U": ["    ", "█  █", "█__█", "▀▀▀▀"],
}

def word(text):
    return [" ".join(LETTERS[c][i] for c in text) for i in range(4)]

def build():
    import lion2
    a = lion2.to_cells(lion2.lion(True))
    un = lion2.to_cells(lion2.mirror(lion2.lion(False)))
    koma, inu = word("KOMA"), word("INU")
    pad_top = len(a) - 4
    kw, iw = len(koma[1]), len(inu[1])
    left = [a[i] + "  " + (koma[i - pad_top] if i >= pad_top else " " * kw) for i in range(len(a))]
    right = [(inu[i - pad_top] if i >= pad_top else " " * iw) + "  " + un[i] for i in range(len(un))]
    return {"left": left, "right": right, "compact": {"left": koma, "right": inu}}

def render(logo, path, cell=(12, 24)):
    BG, DIM, BRIGHT = (14, 14, 18), (128, 128, 140), (240, 240, 245)
    def shade(fg): return tuple(int(BG[i] + (fg[i] - BG[i]) * 0.25) for i in range(3))
    rows = [(l, r) for l, r in zip(logo["left"], logo["right"])]
    width = max(len(l) + 1 + len(r) for l, r in rows) + 4
    cw, ch = cell
    img = Image.new("RGB", (width * cw, (len(rows) + 2) * ch), BG)
    d = ImageDraw.Draw(img)
    def draw(x, y, c, fg):
        sh = shade(fg); X, Y = x * cw, y * ch; half = ch // 2
        top = bot = None
        if c == "█": top = bot = fg
        elif c == "▀": top = fg
        elif c == "▄": bot = fg
        elif c == "_": top = bot = sh
        elif c == "^": top, bot = fg, sh
        elif c == "~": top = sh
        elif c == ",": bot = sh
        elif c == ";": top, bot = sh, fg
        if top: d.rectangle([X, Y, X + cw - 1, Y + half - 1], fill=top)
        if bot: d.rectangle([X, Y + half, X + cw - 1, Y + ch - 1], fill=bot)
    for y, (l, r) in enumerate(rows):
        for x, c in enumerate(l): draw(x + 2, y + 1, c, DIM)
        for x, c in enumerate(r): draw(x + 2 + len(l) + 1, y + 1, c, BRIGHT)
    img.save(path)

if __name__ == "__main__":
    logo = build()
    render(logo, "preview.png")
    render(logo["compact"], "preview-compact.png")
    json.dump(logo, open("logo.json", "w"), ensure_ascii=False, indent=1)
    for l, r in zip(logo["left"], logo["right"]): print(l + " " + r)
