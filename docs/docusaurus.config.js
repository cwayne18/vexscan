// @ts-check
// Docusaurus configuration for the vexscan documentation site.
// Deployed to GitHub Pages at https://cwayne18.github.io/vexscan/

import {themes as prismThemes} from 'prism-react-renderer';

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'vexscan',
  tagline: 'Is this CVE actually present, and can it actually run?',
  favicon: 'img/favicon.ico',

  url: 'https://cwayne18.github.io',
  baseUrl: '/vexscan/',

  organizationName: 'cwayne18',
  projectName: 'vexscan',

  onBrokenLinks: 'warn',

  markdown: {
    hooks: {
      onBrokenMarkdownLinks: 'warn',
    },
  },

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          routeBasePath: '/',
          sidebarPath: './sidebars.js',
          editUrl: 'https://github.com/cwayne18/vexscan/tree/main/docs/',
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      image: 'img/vexscan-social-card.png',
      navbar: {
        title: 'vexscan',
        items: [
          {
            type: 'docSidebar',
            sidebarId: 'docsSidebar',
            position: 'left',
            label: 'Docs',
          },
          {
            href: 'https://github.com/cwayne18/vexscan',
            label: 'GitHub',
            position: 'right',
          },
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: 'Docs',
            items: [
              {label: 'Introduction', to: '/'},
              {label: 'Quick start', to: '/quick-start'},
              {label: 'Known limits', to: '/known-limits'},
            ],
          },
          {
            title: 'More',
            items: [
              {label: 'GitHub', href: 'https://github.com/cwayne18/vexscan'},
            ],
          },
        ],
        copyright: `Copyright © ${new Date().getFullYear()} cwayne18. Built with Docusaurus.`,
      },
      prism: {
        theme: prismThemes.github,
        darkTheme: prismThemes.dracula,
        additionalLanguages: ['bash', 'json'],
      },
    }),
};

export default config;
