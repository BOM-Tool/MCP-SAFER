from rich.text import Text
from rich.console import Console


def make_console() -> Console:
    return Console()


def hex_to_rgb(hex_color: str) -> tuple[int, int, int]:
    hex_color = hex_color.lstrip("#")
    return int(hex_color[0:2], 16), int(hex_color[2:4], 16), int(hex_color[4:6], 16)


def lerp(start: int, end: int, t: float) -> int:
    return int(start + (end - start) * t)


def mix_hex(c1: str, c2: str, t: float) -> str:
    r1, g1, b1 = hex_to_rgb(c1)
    r2, g2, b2 = hex_to_rgb(c2)
    mixed_r = lerp(r1, r2, t)
    mixed_g = lerp(g1, g2, t)
    mixed_b = lerp(b1, b2, t)
    return f"#{mixed_r:02x}{mixed_g:02x}{mixed_b:02x}"


def build_gradient_text(text: str, start_hex: str, end_hex: str, bold: bool = True) -> Text:
    result = Text()
    text_len = len(text)
    
    if text_len == 0:
        return result
    
    for i, char in enumerate(text):
        mix_factor = i / (text_len - 1) if text_len > 1 else 0.0
        gradient_color = mix_hex(start_hex, end_hex, mix_factor)
        style = f"bold {gradient_color}" if bold else gradient_color
        result.append(char, style=style)
    
    return result