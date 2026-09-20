// @ts-check

/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  docsSidebar: [
    'intro',
    'quick-start',
    'selecting-what-to-check',
    {
      type: 'category',
      label: 'Scanning targets',
      link: {type: 'doc', id: 'guides/index'},
      collapsed: false,
      items: [
        'guides/fleet',
        'guides/haul',
        'guides/rootfs',
        'guides/package-files',
        'guides/sbom',
      ],
    },
    'advisories',
    'how-the-tests-work',
    'known-limits',
    'llm-layer',
    {
      type: 'category',
      label: 'Output and reporting',
      link: {type: 'doc', id: 'output/index'},
      collapsed: false,
      items: [
        'output/reports',
        'output/severity-and-filtering',
        'output/vex-sources',
        'output/vex-output',
        'output/machine-formats',
      ],
    },
    'flags',
    'requirements',
    'install',
    'caveats',
  ],
};

export default sidebars;
