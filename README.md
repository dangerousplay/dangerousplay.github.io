# Dangerousplay — Davi Henrique

**Philosopher · Platform Engineer · Furry Lion**

[![Deploy to GitHub Pages](https://github.com/dangerousplay/dangerousplay.github.io/actions/workflows/deploy.yml/badge.svg)](https://github.com/dangerousplay/dangerousplay.github.io/actions/workflows/deploy.yml)

🌐 **[dangerousplay.github.io](https://dangerousplay.github.io)** · 🇧🇷 [Português](https://dangerousplay.github.io/pt/)

![Dangerousplay website preview](public/itemPreview.png)

> *"Knowledge has the power to transform realities."*

## About me

I'm Davi Henrique, a philosopher, philanthropist at heart, and platform engineer from Brazil. I believe the pursuit of knowledge and wisdom is one of the most noble things a person can do, and that it only matters if it's shared.

I started out writing Java backends for a Minecraft server, keeping a small world running for thousands of players. Since then I've built and cared for the systems other people depend on. To me, good engineering is a form of service: building environments where applications thrive, tools that free people from toil, and platforms that stay fast, secure, and trustworthy for everyone who uses them.

I also love talking about profound subjects: the nature of reality, the meaning of life, the ethics of how we treat each other. Philosophy helps me understand the world, and engineering lets me change a small part of it. I want to leave the world more seamless than I found it.

### What I believe

- **Knowledge transforms realities.** Learning is how people and communities change their circumstances, so I write and teach in the open.
- **Technology should serve people.** Systems are worth building when they make someone's life easier, safer, or freer.
- **Helping others is the point.** I work best alongside others: troubleshooting together, sharing what I know, and lifting others up.
- **Always trying to be better,** as an engineer, a thinker, and a person.

### Current initiative — [Novatera.org](https://novatera.org)

Novatera is a philanthropy platform that connects people and inspires good. It's where I'm putting what I know about building systems to work for the common good.

### Tools I bring

- **Platform & DevOps**: Kubernetes, containers, Terraform, Ansible, Packer, GitHub and GitLab CI/CD
- **Observability**: Prometheus, Grafana, OpenTelemetry, Jaeger
- **Security**: HashiCorp Vault, OAuth2/OIDC, SAML, JWT, formal methods (Z3)
- **Backend**: Java, Kotlin, Go, Rust, Scala, Groovy, TypeScript/Node.js, Python, C
- **APIs & data**: REST, gRPC, RSocket, WebSockets, Apache Kafka, PostgreSQL, MySQL, Oracle, MongoDB, Redis

## About this site

A place to share what I learn. I write about platform engineering, distributed systems, security, formal methods, and philosophy. Some posts include interactive demos that run entirely in the browser:

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
