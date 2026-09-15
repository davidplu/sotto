// Guide page HTML: the single renderer for guide routes (`/<slug>`).
//
// React (`SeoPage`) and the build (`seoPrerenderPlugin`) both call
// `snapshotFor`, so the prerendered copy and the interactive page are the
// same string by construction - the text-identical invariant holds
// structurally here, unlike the landing snapshot, which is maintained by
// hand beside `src/Landing.tsx`.
//
// The content below is authored constants from `pages.ts`, never user input,
// so building HTML by string concatenation is safe. Everything is escaped on
// the way out regardless.
//
import { guidePages, type SeoPageData, type SeoTerminalLine } from "./pages";

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// Prose fields: escaped, with `backticks` promoted to <code>.
function inline(text: string): string {
  return escapeHtml(text).replace(/`([^`]+)`/g, "<code>$1</code>");
}

const TERMINAL_PROMPT = '<span class="dim">$</span> ';

function terminalHtml(lines: SeoTerminalLine[]): string {
  const rendered = lines.map((line) => {
    const text = escapeHtml(line.text);
    switch (line.kind) {
      case "cmd":
        return `${TERMINAL_PROMPT}${text}`;
      case "dim":
        return `<span class="dim">${text}</span>`;
      case "value":
        return `<span class="value">${text}</span>`;
    }
  });
  return `<pre class="term"><code>${rendered.join("\n")}</code></pre>`;
}

export function guideLinksHtml(excludeSlug?: string): string {
  return guidePages
    .filter((page) => page.slug !== excludeSlug)
    .map((page) => `<a href="/${escapeHtml(page.slug)}">${escapeHtml(page.navLabel)}</a>`)
    .join("");
}

function footerHtml(page: SeoPageData): string {
  const guides = guideLinksHtml(page.slug);
  return `<footer><nav aria-label="Guides">${guides}<a href="/#pricing">Pricing</a><a href="https://github.com/getsotto/sotto">GitHub</a></nav><p class="muted">Sotto: end-to-end encrypted secret sync. Apache-2.0.</p></footer>`;
}

export function snapshotFor(page: SeoPageData): string {
  const steps = page.steps
    .map((step) => `<li><strong>${inline(step.head)}</strong> ${inline(step.body)}</li>`)
    .join("");
  const faqs = page.faqs
    .map(
      (faq, index) =>
        `<details${index === 0 ? " open" : ""}><summary>${escapeHtml(faq.q)}</summary><p>${inline(faq.a)}</p></details>`,
    )
    .join("");
  return `<main class="seo">
<header class="mast"><a class="wordmark" href="/">Sotto</a><nav class="site" aria-label="Site"><a href="/#how">How it works</a><a href="/#pricing">Pricing</a><a href="https://github.com/getsotto/sotto">GitHub</a><a href="/app">Log in</a></nav></header>
<section class="plain"><h1>${escapeHtml(page.h1)}</h1><p class="lead">${inline(page.lead)}</p><div class="cta-row"><a class="btn primary" href="/#start">Get Sotto</a><a class="btn ghost" href="${escapeHtml(page.ctaSecondary.href)}">${escapeHtml(page.ctaSecondary.label)}</a></div></section>
<section><h2>${escapeHtml(page.stepsTitle)}</h2><ol class="steps">${steps}</ol>${terminalHtml(page.terminal)}</section>
<section><h2>Questions, answered</h2>${faqs}</section>
<section><h2>${escapeHtml(page.closingTitle)}</h2><p>${inline(page.closingBody)}</p><div class="cta-row"><a class="btn primary" href="/#start">Get Sotto</a></div></section>
${footerHtml(page)}
</main>`;
}

// FAQ structured data for the guide page head. Plain text answers - backticks
// are markup for the visible page, not for the data block.
export function faqJsonLd(page: SeoPageData): string {
  const plain = (text: string): string => text.replace(/`/g, "");
  const json = JSON.stringify({
    "@context": "https://schema.org",
    "@type": "FAQPage",
    mainEntity: page.faqs.map((faq) => ({
      "@type": "Question",
      name: plain(faq.q),
      acceptedAnswer: { "@type": "Answer", text: plain(faq.a) },
    })),
  });
  // `<` is escaped so that no answer can close the script element early.
  return `<script type="application/ld+json">${json.replace(/</g, "\\u003c")}</script>`;
}
