import { defineConfig } from 'astro/config';
import mdx from '@astrojs/mdx';
import sitemap from '@astrojs/sitemap';
import tailwind from "@astrojs/tailwind";

// https://astro.build/config
import remarkMath from "remark-math";
import rehypeMathjaxChtml from 'rehype-mathjax/chtml.js'


// https://astro.build/config
export default defineConfig({
  site: 'https://dangerousplay.github.io',
  integrations: [mdx(), sitemap(), tailwind()],
    markdown: {
        remarkPlugins: [remarkMath],
        rehypePlugins: [
            [rehypeMathjaxChtml, {
                chtml: {
                    fontURL: 'https://cdn.jsdelivr.net/npm/mathjax@3/es5/output/chtml/fonts/woff-v2'
                }
            }]
        ],
    }
});