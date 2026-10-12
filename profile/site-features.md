# Personal Blog — Features

> What the redesigned site does and the stack that powers it. Source of truth
> for scoping the new design. Built on the Astrofy template, heavily customized.

## Stack

| Layer        | Tech |
|--------------|------|
| Framework    | Astro 6 (`rustCompiler` experimental) |
| Styling      | Tailwind CSS 4 (Vite plugin) + daisyUI 5 + `@tailwindcss/typography` |
| Interactivity| React 19 islands (`@astrojs/react`) |
| Icons        | `astro-icon` + Iconify (`@iconify-json/simple-icons`, `@iconify-json/lucide`) |
| Content      | Markdown + MDX (`@astrojs/mdx`), content collections |
| Math         | `remark-math` + `rehype-mathjax/chtml` (CHTML output) |
| Feeds/SEO    | `@astrojs/rss`, `@astrojs/sitemap`, `robots.txt` |
| Images       | `sharp` (webp/avif heroes) |
| Solver demo  | `z3-solver` (WASM) + `coi-serviceworker` for cross-origin isolation |
| Vault demo   | `hcl2-parser` for HCL policy parsing |
| Dates        | `dayjs` |
| Package mgr  | pnpm 10 |

## Pages / Routes

- `/` — Home (hero, tech stack rail, Novatera initiative, 3 pillars, latest blog, contact CTA)
- `/projects` — Projects (Novatera, Vault checker, Heap Sort, Z3-in-browser)
- `/blog` + `/blog/[slug]` — paginated blog index + post pages
- `/cv` — Resume (profile, education, experience, certifications, skills timeline)
- `/404`
- `/rss.xml`
- `/design-lab` — design proposal sandbox (dev)
- Portuguese mirror under `/pt/*`

## Features

- **i18n** — EN (default, no prefix) + PT (`/pt`). Keyed strings in `src/i18n/ui.ts`, helpers in `utils.ts`. `LanguageSwitcher` component.
- **Theming** — light "studio" theme + dark, `ThemeToggle` component.
- **Tech stack rail** — branded brand-coloured icons with hover glow, driven by `src/data/tech.ts` (curated subset). Full inventory lives in `profile/tech-stack.ts`.
- **Interactive demos** — Z3 SMT solver and Vault escalation policy checker run client-side via WASM.
- **Math rendering** — LaTeX in posts via MathJax CHTML.
- **Content collections** — typed blog frontmatter (`src/content.config.ts`).
- **RSS + sitemap + SEO** — `BaseHead` meta, OG image (`itemPreview.png`).
- **CV timeline** — `components/cv/TimeLine.astro`.
- **Stickers / mascot** — furry-lion persona assets under `public/stickers/`.

## Identity wired into the site

- Title: `Dangerousplay | Philosopher · Platform Engineer · Furry Lion`
- Eyebrow: `Philosopher · Platform Engineer · Furry Lion`
- Location: Brazil · Languages: EN · PT · Focus: Platform & Security
- Current initiative: **Novatera.org** — philanthropy platform to connect people and inspire good.

## Component inventory

`BaseHead`, `Header`, `Footer`, `SideBar(+Menu/Footer)`, `Card`, `HorizontalCard`,
`HorizontalShopItem`, `TechStack`, `TechBadge`, `LanguageSwitcher`, `ThemeToggle`,
`DesignProposalSwitcher`, `cv/TimeLine`, `vault/EscalationPolicyChecker`.
