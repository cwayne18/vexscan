# vexscan documentation site

This folder holds the [Docusaurus](https://docusaurus.io/) source for the
vexscan documentation, published to GitHub Pages at
<https://cwayne18.github.io/vexscan/>.

## Local development

```sh
cd docs
npm install
npm start        # live-reload dev server at http://localhost:3000/vexscan/
npm run build    # production build into docs/build
```

Docs content lives in `docs/docs/`. The sidebar is defined in `sidebars.js`.
Deployment is automated by `.github/workflows/docs.yml` on pushes to `main`
that touch `docs/`.
