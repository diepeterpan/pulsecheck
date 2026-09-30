import math
import os
from pathlib import Path
from PIL import Image, ImageDraw, ImageFilter

STATIC_DIR = Path(__file__).parent / "static"

def get_ecg_point(norm_x):
    """
    Returns normalized y (0.0 to 1.0) for an ECG waveform across x in [0.0, 1.0].
    Baseline is at y = 0.52.
    """
    x = norm_x % 1.0
    baseline = 0.52

    # Segment boundaries
    # 0.00 - 0.16 : lead-in baseline
    # 0.16 - 0.28 : P wave (smooth rounded upward bump)
    # 0.28 - 0.36 : PR segment baseline
    # 0.36 - 0.40 : Q wave (sharp dip)
    # 0.40 - 0.46 : R wave (sharp tall peak)
    # 0.46 - 0.52 : S wave (sharp valley)
    # 0.52 - 0.60 : ST segment baseline
    # 0.60 - 0.78 : T wave (smooth rounded upward wave)
    # 0.78 - 1.00 : lead-out baseline

    if 0.16 <= x < 0.28:
        # P wave
        p = (x - 0.16) / 0.12
        return baseline - 0.055 * math.sin(p * math.pi)
    elif 0.36 <= x < 0.40:
        # Q wave dip
        p = (x - 0.36) / 0.04
        return baseline + 0.065 * math.sin(p * math.pi)
    elif 0.40 <= x < 0.46:
        # R wave peak
        p = (x - 0.40) / 0.06
        if p < 0.5:
            # Upslope to peak
            t = p / 0.5
            return baseline - 0.38 * t
        else:
            # Downslope from peak to S valley
            t = (p - 0.5) / 0.5
            return (baseline - 0.38) + (0.38 + 0.20) * t
    elif 0.46 <= x < 0.52:
        # S wave recovery to baseline
        p = (x - 0.46) / 0.06
        return (baseline + 0.20) - 0.20 * math.sin(p * math.pi * 0.5)
    elif 0.60 <= x < 0.78:
        # T wave
        p = (x - 0.60) / 0.18
        return baseline - 0.095 * math.sin(p * math.pi)
    else:
        return baseline

def draw_monitor_grid(draw, width, height, grid_spacing=24, major_every=4):
    """Draws subtle monitor grid lines on a white background."""
    grid_color_minor = (241, 245, 249, 255)  # slate-100
    grid_color_major = (226, 232, 240, 255)  # slate-200

    # Vertical grid lines
    col = 0
    for x in range(0, width + 1, grid_spacing):
        color = grid_color_major if (col % major_every == 0) else grid_color_minor
        draw.line([(x, 0), (x, height)], fill=color, width=1)
        col += 1

    # Horizontal grid lines
    row = 0
    for y in range(0, height + 1, grid_spacing):
        color = grid_color_major if (row % major_every == 0) else grid_color_minor
        draw.line([(0, y), (width, y)], fill=color, width=1)
        row += 1

def generate_static_logo(size=512):
    """Generates high-resolution static logo with green heartbeat on white background."""
    scale = 2
    canvas_size = size * scale
    img = Image.new("RGBA", (canvas_size, canvas_size), (255, 255, 255, 255))
    draw = ImageDraw.Draw(img)

    # 1. Monitor grid
    draw_monitor_grid(draw, canvas_size, canvas_size, grid_spacing=32 * scale, major_every=4)

    # Margins and waveform area (proportional to canvas size)
    pad_x = max(4, int(canvas_size * 0.05))
    pad_y = max(4, int(canvas_size * 0.06))
    draw_w = canvas_size - (pad_x * 2)
    draw_h = canvas_size - (pad_y * 2)

    # Precalculate dense ECG coordinates
    steps = 400
    points = []
    for i in range(steps + 1):
        nx = i / steps
        ny = get_ecg_point(nx)
        px = pad_x + nx * draw_w
        py = pad_y + ny * draw_h
        points.append((px, py))

    # 2. Outer soft green glow
    glow_img = Image.new("RGBA", (canvas_size, canvas_size), (0, 0, 0, 0))
    glow_draw = ImageDraw.Draw(glow_img)
    glow_width = int(14 * scale)
    glow_draw.line(points, fill=(52, 211, 153, 90), width=glow_width, joint="curve")
    glow_img = glow_img.filter(ImageFilter.GaussianBlur(radius=6 * scale))
    img.alpha_composite(glow_img)

    # 3. Secondary glow line
    draw = ImageDraw.Draw(img)
    mid_width = int(7 * scale)
    draw.line(points, fill=(16, 185, 129, 160), width=mid_width, joint="curve")

    # 4. Core crisp green heartbeat line
    core_width = int(4 * scale)
    draw.line(points, fill=(21, 128, 61, 255), width=core_width, joint="curve")

    # 5. Core bright vibrant center
    inner_width = int(2.2 * scale)
    draw.line(points, fill=(34, 197, 94, 255), width=inner_width, joint="curve")

    # 6. R-peak pulse node (small glowing accent at apex)
    r_peak_nx = 0.43
    r_px = pad_x + r_peak_nx * draw_w
    r_py = pad_y + get_ecg_point(r_peak_nx) * draw_h
    node_r = 5 * scale
    draw.ellipse([(r_px - node_r, r_py - node_r), (r_px + node_r, r_py + node_r)], fill=(34, 197, 94, 255))
    draw.ellipse([(r_px - node_r * 0.5, r_py - node_r * 0.5), (r_px + node_r * 0.5, r_py + node_r * 0.5)], fill=(255, 255, 255, 220))

    # Downsample with high quality Lanczos filter
    final_img = img.resize((size, size), Image.Resampling.LANCZOS)
    return final_img

def generate_favicon(size):
    """Generates crisp favicon optimized for very small sizes (16x16, 32x32, 48x48)."""
    scale = 4
    canvas_size = size * scale
    img = Image.new("RGBA", (canvas_size, canvas_size), (255, 255, 255, 255))
    draw = ImageDraw.Draw(img)

    # Subtle soft border/grid
    draw.rectangle([(0, 0), (canvas_size - 1, canvas_size - 1)], outline=(226, 232, 240, 255), width=1 * scale)

    pad_x = 2 * scale
    pad_y = 3 * scale
    draw_w = canvas_size - (pad_x * 2)
    draw_h = canvas_size - (pad_y * 2)

    steps = 100
    points = []
    for i in range(steps + 1):
        nx = i / steps
        ny = get_ecg_point(nx)
        px = pad_x + nx * draw_w
        py = pad_y + ny * draw_h
        points.append((px, py))

    # Bold green stroke to remain sharp and legible at tiny sizes
    stroke_width = max(2, int(size * 0.16 * scale))
    draw.line(points, fill=(22, 163, 74, 255), width=stroke_width, joint="curve")

    # Bright center line
    inner_width = max(1, int(stroke_width * 0.6))
    draw.line(points, fill=(34, 197, 94, 255), width=inner_width, joint="curve")

    return img.resize((size, size), Image.Resampling.LANCZOS)

def generate_animated_gif(size=128, num_frames=36, fps=24):
    """
    Generates an animated GIF of the green heartbeat pulsing left-to-right
    with fading shades of green as it beats on a white background.
    """
    scale = 2
    canvas_size = size * scale
    frames = []

    # Monitor grid pre-render
    base_grid = Image.new("RGBA", (canvas_size, canvas_size), (255, 255, 255, 255))
    grid_draw = ImageDraw.Draw(base_grid)
    draw_monitor_grid(grid_draw, canvas_size, canvas_size, grid_spacing=20 * scale, major_every=4)

    pad_x = 12 * scale
    pad_y = 16 * scale
    draw_w = canvas_size - (pad_x * 2)
    draw_h = canvas_size - (pad_y * 2)

    # Total dense points along the ECG
    total_steps = 300
    all_points = []
    for i in range(total_steps + 1):
        nx = i / total_steps
        ny = get_ecg_point(nx)
        px = pad_x + nx * draw_w
        py = pad_y + ny * draw_h
        all_points.append((nx, px, py))

    trail_length = 0.70  # fraction of screen trail remains visible

    # Shades of green palette from newest/brightest to oldest/fading:
    # 0.0 (head): Bright vibrant green (34, 197, 94)
    # 0.2: Emerald green (16, 185, 129)
    # 0.4: Medium forest green (22, 163, 74)
    # 0.6: Deep jade (5, 150, 105)
    # 0.8: Soft sage green (110, 231, 183) fading into background

    def get_trail_color(age_fraction):
        """Returns RGBA tuple for a point given its normalized age behind the sweep head [0.0, 1.0]."""
        # Interpolate shades of green
        if age_fraction < 0.15:
            # Lead segment: intense bright emerald
            t = age_fraction / 0.15
            r = int(34 + (16 - 34) * t)
            g = int(197 + (185 - 197) * t)
            b = int(94 + (129 - 94) * t)
            alpha = int(255 - 15 * t)
        elif age_fraction < 0.40:
            # Medium emerald to forest green
            t = (age_fraction - 0.15) / 0.25
            r = int(16 + (21 - 16) * t)
            g = int(185 + (128 - 185) * t)
            b = int(129 + (61 - 129) * t)
            alpha = int(240 - 50 * t)
        elif age_fraction < 0.75:
            # Fading deeper/softer green
            t = (age_fraction - 0.40) / 0.35
            r = int(21 + (74 - 21) * t)
            g = int(128 + (222 - 128) * t)
            b = int(61 + (128 - 61) * t)
            alpha = int(190 - 110 * t)
        else:
            # Final fade to invisible
            t = (age_fraction - 0.75) / 0.25
            r, g, b = 134, 239, 172
            alpha = int(max(0, 80 * (1.0 - t)))
        return (r, g, b, alpha)

    # R-peak location in norm_x is ~0.43
    r_peak_nx = 0.43
    r_px = pad_x + r_peak_nx * draw_w
    r_py = pad_y + get_ecg_point(r_peak_nx) * draw_h

    for f in range(num_frames):
        # Progress of sweep head [0.0 to 1.0]
        sweep_x = f / num_frames

        frame = base_grid.copy()

        # 1. Draw subtle ghost/historical baseline trace (so the waveform shape is softly perceived)
        ghost_layer = Image.new("RGBA", (canvas_size, canvas_size), (0, 0, 0, 0))
        ghost_draw = ImageDraw.Draw(ghost_layer)
        pts_coords = [(pt[1], pt[2]) for pt in all_points]
        ghost_draw.line(pts_coords, fill=(220, 252, 231, 140), width=int(2 * scale), joint="curve")  # soft green-50
        frame.alpha_composite(ghost_layer)

        # 2. Draw Heartbeat Pulse Glow when sweep is at/after R peak (frames around sweep_x = 0.40 to 0.70)
        # Pulse radiates outward and fades in shades of green
        dist_from_r = (sweep_x - r_peak_nx) % 1.0
        if 0.0 <= dist_from_r < 0.35:
            beat_progress = dist_from_r / 0.35  # 0.0 to 1.0
            pulse_layer = Image.new("RGBA", (canvas_size, canvas_size), (0, 0, 0, 0))
            pulse_draw = ImageDraw.Draw(pulse_layer)

            # Expanding concentric pulse rings in fading shades of green
            ring_r = (8 + 36 * beat_progress) * scale
            ring_alpha = int(180 * (1.0 - beat_progress) ** 1.5)
            # Shade shifts from emerald to mint as it expands and fades
            ring_g = int(220 - 40 * beat_progress)
            ring_b = int(94 + 60 * beat_progress)
            ring_width = max(1, int((3 - 2 * beat_progress) * scale))

            pulse_draw.ellipse(
                [(r_px - ring_r, r_py - ring_r), (r_px + ring_r, r_py + ring_r)],
                outline=(34, ring_g, ring_b, ring_alpha),
                width=ring_width
            )

            # Inner secondary soft pulse glow
            inner_r = ring_r * 0.55
            inner_alpha = int(130 * (1.0 - beat_progress) ** 2)
            pulse_draw.ellipse(
                [(r_px - inner_r, r_py - inner_r), (r_px + inner_r, r_py + inner_r)],
                fill=(52, 211, 153, inner_alpha)
            )

            pulse_layer = pulse_layer.filter(ImageFilter.GaussianBlur(radius=2 * scale))
            frame.alpha_composite(pulse_layer)

        # 3. Draw Active Pulsing Trace with Fading Phosphor Trail
        trace_layer = Image.new("RGBA", (canvas_size, canvas_size), (0, 0, 0, 0))
        trace_draw = ImageDraw.Draw(trace_layer)

        # We draw segments along all_points that fall within the active trail
        for i in range(len(all_points) - 1):
            nx1, px1, py1 = all_points[i]
            nx2, px2, py2 = all_points[i + 1]

            # Calculate distance behind sweep head
            # If point is behind sweep head in current cycle:
            # age = (sweep_x - nx) % 1.0
            age = (sweep_x - nx1) % 1.0

            if age <= trail_length:
                age_frac = age / trail_length  # 0.0 at head, 1.0 at tail end
                color = get_trail_color(age_frac)

                # Line thickness tapers gracefully from 3.5*scale down to 1.5*scale
                w = max(1, int((3.5 - 2.0 * age_frac) * scale))

                # If near R-peak and actively beating, amplify thickness slightly
                if 0.40 <= nx1 <= 0.46 and 0.0 <= dist_from_r < 0.20:
                    w += int(1.5 * scale * (1.0 - dist_from_r / 0.20))

                trace_draw.line([(px1, py1), (px2, py2)], fill=color, width=w)

        # 4. Leading sweep cursor (bright glowing point at head of heartbeat)
        head_ny = get_ecg_point(sweep_x)
        head_px = pad_x + sweep_x * draw_w
        head_py = pad_y + head_ny * draw_h

        # Head glow halo
        cursor_layer = Image.new("RGBA", (canvas_size, canvas_size), (0, 0, 0, 0))
        c_draw = ImageDraw.Draw(cursor_layer)
        glow_r = 7 * scale
        c_draw.ellipse(
            [(head_px - glow_r, head_py - glow_r), (head_px + glow_r, head_py + glow_r)],
            fill=(74, 222, 128, 140)
        )
        cursor_layer = cursor_layer.filter(ImageFilter.GaussianBlur(radius=2 * scale))
        frame.alpha_composite(cursor_layer)

        # Crisp core sweep dot
        t_draw = ImageDraw.Draw(trace_layer)
        dot_r = 3.5 * scale
        t_draw.ellipse(
            [(head_px - dot_r, head_py - dot_r), (head_px + dot_r, head_py + dot_r)],
            fill=(34, 197, 94, 255)
        )
        # Center white highlight
        t_draw.ellipse(
            [(head_px - dot_r * 0.45, head_py - dot_r * 0.45), (head_px + dot_r * 0.45, head_py + dot_r * 0.45)],
            fill=(255, 255, 255, 240)
        )

        frame.alpha_composite(trace_layer)

        # Downsample for smooth antialiasing
        final_frame = frame.resize((size, size), Image.Resampling.LANCZOS)
        # Convert to RGB (white background)
        rgb_frame = Image.new("RGB", (size, size), (255, 255, 255))
        rgb_frame.paste(final_frame, mask=final_frame.split()[3])
        frames.append(rgb_frame)

    return frames

def main():
    print("Generating assets...")
    STATIC_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Static logos
    print("1. Generating logo-full.png (1024x1024)...")
    logo_full = generate_static_logo(size=1024)
    logo_full.save(STATIC_DIR / "logo-full.png", format="PNG", optimize=True)

    print("2. Generating logo.png (512x512)...")
    logo_512 = generate_static_logo(size=512)
    logo_512.save(STATIC_DIR / "logo.png", format="PNG", optimize=True)

    print("3. Generating apple-touch-icon.png (180x180)...")
    apple_touch = generate_static_logo(size=180)
    apple_touch.save(STATIC_DIR / "apple-touch-icon.png", format="PNG", optimize=True)

    print("4. Generating logo-email.png (64x64, downsampled from logo.png for email headers)...")
    logo_email = logo_512.resize((64, 64), Image.Resampling.LANCZOS)
    logo_email.save(STATIC_DIR / "logo-email.png", format="PNG", optimize=True)

    # 2. Favicons
    print("4. Generating favicon-32x32.png and 16x16.png...")
    fav_32 = generate_favicon(32)
    fav_32.save(STATIC_DIR / "favicon-32x32.png", format="PNG")

    fav_16 = generate_favicon(16)
    fav_16.save(STATIC_DIR / "favicon-16x16.png", format="PNG")

    fav_48 = generate_favicon(48)
    fav_32_rgb = Image.new("RGBA", (32, 32), (255, 255, 255, 255))
    fav_32_rgb.paste(fav_32, mask=fav_32)
    fav_16_rgb = Image.new("RGBA", (16, 16), (255, 255, 255, 255))
    fav_16_rgb.paste(fav_16, mask=fav_16)
    fav_48_rgb = Image.new("RGBA", (48, 48), (255, 255, 255, 255))
    fav_48_rgb.paste(fav_48, mask=fav_48)

    print("5. Generating favicon.ico...")
    fav_48_rgb.save(
        STATIC_DIR / "favicon.ico",
        format="ICO",
        sizes=[(16, 16), (32, 32), (48, 48)]
    )

    # 3. Animated GIF
    print("6. Generating animated logo.gif (160x160, 36 frames, pulsing green on white background)...")
    frames = generate_animated_gif(size=160, num_frames=36, fps=24)
    # Save as animated GIF with 42ms duration per frame (~24fps), looping forever
    frames[0].save(
        STATIC_DIR / "logo.gif",
        save_all=True,
        append_images=frames[1:],
        duration=42,
        loop=0,
        optimize=True
    )

    print("All assets successfully generated!")

if __name__ == "__main__":
    main()
