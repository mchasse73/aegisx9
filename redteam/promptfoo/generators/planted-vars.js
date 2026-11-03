// transformVars hook: fills `planted` from the generator named by `kind`, at runtime, so no
// credential-shaped literal is stored. promptfoo resolves file:// from the config directory.
const planted = require("./planted");

module.exports = (vars) => {
  if (vars.kind === undefined) return vars;
  const make = planted[vars.kind];
  if (typeof make !== "function") throw new Error(`unknown planted kind: ${vars.kind}`);
  return { ...vars, planted: make() };
};
