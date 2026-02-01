// @ts-check
import { defineConfig } from 'astro/config';

import tailwindcss from '@tailwindcss/vite';

// https://astro.build/config
export default defineConfig({
  site: 'https://www.rifkan.de',
  image: {
    domains: ['images.unsplash.com', 'cdn.simpleicons.org'],
  },
  vite: {
    plugins: [tailwindcss()]
  }
});