"""
Unit tests for service icon contrast evaluation and color negation.
"""
from __future__ import annotations

import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from PIL import Image

import services.icons as icon_service


class TestIconContrastEvaluation(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.svc_dir = Path(self.temp_dir.name) / "service_icons"
        self.mfg_dir = Path(self.temp_dir.name) / "manufacturer_icons"
        self.svc_dir.mkdir(parents=True, exist_ok=True)
        self.mfg_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_parse_color_to_rgb(self):
        self.assertEqual(icon_service.parse_color_to_rgb("#fff"), (255, 255, 255))
        self.assertEqual(icon_service.parse_color_to_rgb("#ffffff"), (255, 255, 255))
        self.assertEqual(icon_service.parse_color_to_rgb("white"), (255, 255, 255))
        self.assertEqual(icon_service.parse_color_to_rgb("snow"), (255, 250, 250))
        self.assertEqual(icon_service.parse_color_to_rgb("rgb(255, 255, 255)"), (255, 255, 255))
        self.assertEqual(icon_service.parse_color_to_rgb("rgba(255, 255, 255, 0.8)"), (255, 255, 255))
        self.assertIsNone(icon_service.parse_color_to_rgb("none"))
        self.assertIsNone(icon_service.parse_color_to_rgb("transparent"))
        self.assertIsNone(icon_service.parse_color_to_rgb(""))

    def test_is_near_white_color(self):
        # 10% tolerance threshold: L >= 0.90, Y >= 229.5, S <= 0.15
        self.assertTrue(icon_service.is_near_white_color(255, 255, 255))
        self.assertTrue(icon_service.is_near_white_color(240, 240, 240))  # #f0f0f0
        self.assertTrue(icon_service.is_near_white_color(230, 230, 230))  # #e6e6e6 (exactly 90% lightness)

        # Darker than 10% tolerance from pure white
        self.assertFalse(icon_service.is_near_white_color(220, 220, 220))  # #dcdcdc
        self.assertFalse(icon_service.is_near_white_color(0, 0, 0))  # black
        self.assertFalse(icon_service.is_near_white_color(15, 23, 42))  # slate dark

        # High luminance but high saturation (not white)
        self.assertFalse(icon_service.is_near_white_color(255, 255, 0))  # vivid yellow

    def test_svg_motioneye_negation(self):
        # Real motioneye SVG payload
        motioneye_svg = (
            b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" fill="#fff">'
            b'<path d="M32 6c-5.265 0-10.156 1.685-14.25 4.375z"/></svg>'
        )
        res = icon_service.evaluate_and_adjust_icon_contrast(motioneye_svg, ".svg")
        res_text = res.decode("utf-8")
        self.assertIn('fill="#000000"', res_text)
        self.assertNotIn('fill="#fff"', res_text)

    def test_svg_multicolor_non_regression(self):
        multicolor_svg = (
            b'<svg width="256" height="256" viewBox="0 0 256 256" fill="none" xmlns="http://www.w3.org/2000/svg">'
            b'<rect width="256" height="256" fill="#FF6325"/>'
            b'<path d="M128 50..." fill="white"/>'
            b'</svg>'
        )
        res = icon_service.evaluate_and_adjust_icon_contrast(multicolor_svg, ".svg")
        # Since it has contrasting orange (#FF6325), it should not be negated
        self.assertEqual(res, multicolor_svg)

    def test_svg_without_fills_non_regression(self):
        default_black_svg = b'<svg xmlns="http://www.w3.org/2000/svg" width="25" height="25"><path d="M1 12.5h2.9v7.8h17v-7.8h2.9l-2.9-2.9V4.5h-1.8v3.3L12.3 1 1 12.5Z"/></svg>'
        res = icon_service.evaluate_and_adjust_icon_contrast(default_black_svg, ".svg")
        self.assertEqual(res, default_black_svg)

    def test_raster_png_white_negation(self):
        # Create transparent PNG with white box
        img = Image.new("RGBA", (32, 32), (0, 0, 0, 0))
        for x in range(8, 24):
            for y in range(8, 24):
                img.putpixel((x, y), (255, 255, 255, 255))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        raw_png = buf.getvalue()

        res_png = icon_service.evaluate_and_adjust_icon_contrast(raw_png, ".png")
        out_img = Image.open(io.BytesIO(res_png))

        # Check background remains transparent
        self.assertEqual(out_img.getpixel((0, 0))[3], 0)
        # Check white foreground was inverted to black
        self.assertEqual(out_img.getpixel((16, 16)), (0, 0, 0, 255))

    def test_raster_png_colored_non_regression(self):
        # Create transparent PNG with blue box
        img = Image.new("RGBA", (32, 32), (0, 0, 0, 0))
        for x in range(8, 24):
            for y in range(8, 24):
                img.putpixel((x, y), (37, 99, 235, 255))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        raw_png = buf.getvalue()

        res_png = icon_service.evaluate_and_adjust_icon_contrast(raw_png, ".png")
        out_img = Image.open(io.BytesIO(res_png))

        # Should remain blue
        self.assertEqual(out_img.getpixel((16, 16))[:3], (37, 99, 235))

    def test_raster_opaque_photo_non_regression(self):
        # Opaque image without alpha transparency (e.g. photo/card)
        img = Image.new("RGB", (32, 32), (255, 255, 255))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        raw_png = buf.getvalue()

        res_png = icon_service.evaluate_and_adjust_icon_contrast(raw_png, ".png")
        # Should not invert fully opaque images
        self.assertEqual(res_png, raw_png)

    def test_raster_ico_white_negation(self):
        img = Image.new("RGBA", (32, 32), (0, 0, 0, 0))
        for x in range(8, 24):
            for y in range(8, 24):
                img.putpixel((x, y), (255, 255, 255, 255))
        buf = io.BytesIO()
        img.save(buf, format="ICO")
        raw_ico = buf.getvalue()

        res_ico = icon_service.evaluate_and_adjust_icon_contrast(raw_ico, ".ico")
        out_img = Image.open(io.BytesIO(res_ico))
        self.assertEqual(out_img.getpixel((16, 16))[:3], (0, 0, 0))

    @patch("services.icons.get_service_icons_dir")
    def test_resolve_and_cache_service_icon_applies_contrast_adjustment(self, mock_get_svc_dir):
        mock_get_svc_dir.return_value = self.svc_dir

        motioneye_svg = (
            b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" fill="#fff">'
            b'<path d="M32 6c-5.265 0-10.156 1.685-14.25 4.375z"/></svg>'
        )

        # Mock HTTP manager returning motioneye SVG
        mock_http = MagicMock()
        mock_http.get_url.return_value = (motioneye_svg, 200, {"Content-Type": "image/svg+xml"})

        with patch("services.icons._get_http_manager", return_value=mock_http):
            with patch("services.icons.fetch_service_content_responses", return_value=[]):
                with patch("services.icons.get_service_candidate_endpoints", return_value=[{"base_url": "https://motioneye.local", "url_path": "/"}]):
                    url = icon_service.resolve_and_cache_service_icon("motioneye.local")

        self.assertIsNotNone(url)
        self.assertEqual(url, "/static/service-icons/motioneye.svg")
        saved_file = self.svc_dir / "motioneye.svg"
        self.assertTrue(saved_file.is_file())
        saved_content = saved_file.read_text(encoding="utf-8")
        self.assertIn('fill="#000000"', saved_content)
        self.assertNotIn('fill="#fff"', saved_content)


if __name__ == "__main__":
    unittest.main()
