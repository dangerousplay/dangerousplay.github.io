import { defineConfig } from 'astro/config';
import mdx from '@astrojs/mdx';
import sitemap from '@astrojs/sitemap';
import { viteStaticCopy } from 'vite-plugin-static-copy';

import remarkMath from "remark-math";
import rehypeMathjaxChtml from 'rehype-mathjax/chtml'


import tailwindcss from '@tailwindcss/vite';
import react from '@astrojs/react';


// https://astro.build/config
export default defineConfig({
  site: 'https://dangerousplay.github.io',
  integrations: [mdx(), sitemap(), react()],

  markdown: {
      remarkPlugins: [remarkMath],
      rehypePlugins: [
          [rehypeMathjaxChtml, {
              chtml: {
                  fontURL: 'https://cdn.jsdelivr.net/npm/mathjax@3/es5/output/chtml/fonts/woff-v2'
              }
          }]
      ],
  },

  vite: {
    plugins: [
        tailwindcss(),
        viteStaticCopy({
            targets: [
                {
                    src: 'node_modules/z3-solver/build/z3-built.*',
                    dest: ''
                },
                {
                    src: 'node_modules/coi-serviceworker/coi-serviceworker.js',
                    dest: ''
                }
            ]
        }),
        {
          // Plugin code is from https://github.com/chaosprint/vite-plugin-cross-origin-isolation
          name: "configure-response-headers",
          configureServer: (server) => {
            server.middlewares.use((_req, res, next) => {
              res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
              res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
              next();
            });
          },
        }
    ]
  }
});