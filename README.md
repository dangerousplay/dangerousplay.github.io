# Dangerousplay — Davi Henrique

**Philosopher · Platform Engineer · Furry Lion**

[![Deploy to GitHub Pages](https://github.com/dangerousplay/dangerousplay.github.io/actions/workflows/deploy.yml/badge.svg)](https://github.com/dangerousplay/dangerousplay.github.io/actions/workflows/deploy.yml)

🌐 **[dangerousplay.github.io](https://dangerousplay.github.io)** · 🇧🇷 [Português](https://dangerousplay.github.io/pt/)

![Dangerousplay website preview](public/itemPreview.png)

> *"Knowledge has the power to transform realities."*

## About me

I'm Davi Henrique, a philosopher, philanthropist at heart, and platform engineer based in Brazil. I build systems that scale, and I keep asking why they should.

I started out writing Java backends for a Minecraft server. Thousands of players hammering a service in real time taught me a lot about concurrency, low-latency networking, and resilience. Since then I've worked as a backend engineer and architect, and today I'm a **Specialist Platform Engineer at Sicredi**. My job is automating and building the applications behind the whole software-delivery lifecycle.

Outside the terminal I like talking about the nature of reality, the meaning of life, and the ethics of human behavior. Philosophy helps me make sense of the world, and engineering helps me change a small part of it. I want to leave the world more seamless than I found it.

### Current initiative — [Novatera.org](https://novatera.org)

Novatera is a philanthropy platform that connects people and inspires good.

### What I work with

- **Platform & DevOps**: Kubernetes, containers, Terraform, Ansible, Packer, GitHub and GitLab CI/CD
- **Observability**: Prometheus, Grafana, OpenTelemetry, Jaeger
- **Security**: HashiCorp Vault, OAuth2/OIDC, SAML, JWT, formal methods (Z3)
- **Backend**: Java, Kotlin, Go, Rust, Scala, Groovy, TypeScript/Node.js, Python, C
- **APIs & data**: REST, gRPC, RSocket, WebSockets, Apache Kafka, PostgreSQL, MySQL, Oracle, MongoDB, Redis

### Experience & education

| Period | Role |
|---|---|
| 2026 – now | Specialist Platform Engineer, Sicredi |
| 2022 – 2026 | DevOps Developer / Software Engineer, Sicredi |
| 2020 – 2022 | DevOps Software Developer |
| 2018 – 2020 | Junior Software Developer, NTConsult |

- **Postgraduate**: Leadership for Innovation, Unilasalle
- **B.Sc. Computer Science**: Unilasalle, 2023

## About this site

My personal blog and portfolio. I write about platform engineering, distributed systems, security, formal methods, and philosophy. Some posts include interactive demos that run entirely in the browser:

- **[Vault policy escalation checker](https://dangerousplay.github.io/blog/vault_policy_escalation/)**: parses HashiCorp Vault HCL policies and checks them for privilege escalation paths with the Z3 SMT solver (WASM).
- **[Heap Sort](https://dangerousplay.github.io/blog/heap_sort/)**: the algorithm explained, with math rendered by MathJax.

### Stack

| Layer | Tech |
|---|---|
| Framework | [Astro 6](https://astro.build) |
| Styling | Tailwind CSS 4, daisyUI 5 |
| Interactivity | React 19 islands |
| Content | Markdown + MDX content collections, MathJax |
| Demos | `z3-solver` (WASM), `hcl2-parser`, `coi-serviceworker` |
| i18n | English (default) + Portuguese (`/pt`) |
| Deploy | GitHub Actions → GitHub Pages |

### Running locally

Requires Node.js 20+ and pnpm 10.

```bash
pnpm install
pnpm dev       # http://localhost:4321
pnpm build     # static output in dist/
pnpm preview
```

Pushes to `main` are built and deployed by [`.github/workflows/deploy.yml`](.github/workflows/deploy.yml).

### Project layout

```
src/
├── components/   # UI components (TechStack, ThemeToggle, cv/TimeLine, vault/…)
├── content/blog/ # Markdown / MDX posts
├── data/         # Tech stack data for the home page
├── i18n/         # EN / PT strings and helpers
├── layouts/      # Base and post layouts
└── pages/        # Routes (EN at root, PT under /pt)
profile/          # Source-of-truth notes about me and the site
public/           # Static assets, stickers, images
```

## Get in touch

- GitHub: [@dangerousplay](https://github.com/dangerousplay)
- X / Twitter: [@dangerousplayt](https://twitter.com/dangerousplayt)
- Email: [dangerousplay715@gmail.com](mailto:dangerousplay715@gmail.com)

## Credits

Originally based on the [Astrofy](https://github.com/manuelernestog/astrofy) template by Manuel Ernesto Garcia, and heavily customized since. Licensed under the MIT license. See [LICENSE](LICENSE).
