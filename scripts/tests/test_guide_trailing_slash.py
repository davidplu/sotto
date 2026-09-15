"""The Caddyfile must fold trailing-slash guide URLs onto the slugs in pages.ts.

Crawlers and no-script visitors hitting `/<slug>/` used to receive the homepage
snapshot; the edge redirect is what stops that. The slug list lives in
web/src/seo/pages.ts, so this test is the check that Caddy was updated on the
same day as a new guide.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PAGES = ROOT / "web/src/seo/pages.ts"
CADDY = ROOT / "Caddyfile"

SLUG_RE = re.compile(r'^\s+slug: "([a-z0-9-]+)",$', re.MULTILINE)
REDIR_RE = re.compile(r"^[ \t]*redir /([a-z0-9-]+)/ /\1 permanent$", re.MULTILINE)


class GuideTrailingSlashRedirect(unittest.TestCase):
    def test_caddy_redirects_every_guide_slash_to_its_canonical_path(self):
        slugs = SLUG_RE.findall(PAGES.read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(slugs), 1, "pages.ts has no guide slugs")
        redirected = REDIR_RE.findall(CADDY.read_text(encoding="utf-8"))
        self.assertEqual(
            redirected,
            slugs,
            "Caddyfile trailing-slash redirects must match guidePages in pages.ts, in the same order",
        )


if __name__ == "__main__":
    unittest.main()
