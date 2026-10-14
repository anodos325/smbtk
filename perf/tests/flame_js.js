// usage: node flame_js.js FLAME.svg FRAME REGEX
// Runs the flame graph's script on a stand-in DOM: clicks FRAME, resets,
// searches REGEX, and prints what came out as JSON.
const fs = require('fs');
const svg = fs.readFileSync(process.argv[2], 'utf8');
const unesc = s => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>')
  .replace(/&quot;/g, '"').replace(/&#x27;/g, "'").replace(/&amp;/g, '&');
function el(attrs, text) {
  return {
    attrs, textContent: text || '', handlers: {},
    setAttribute(k, v) { this.attrs[k] = String(v); },
    getAttribute(k) { return this.attrs[k]; },
    addEventListener(ev, fn) { this.handlers[ev] = fn; },
  };
}
const re = /<g class="f" data-n="([^"]*)" data-x="([^"]*)" data-w="([^"]*)" data-d="([^"]*)"><title>([^<]*)<\/title><rect x="([^"]*)" y="([^"]*)" width="([^"]*)" height="[^"]*" fill="([^"]*)"\/><text x="([^"]*)" y="[^"]*">([^<]*)<\/text><\/g>/g;
const frames = [];
let m;
while ((m = re.exec(svg)) !== null) {
  const rect = el({x: m[6], y: m[7], width: m[8], fill: m[9]});
  const text = el({x: m[10]}, unesc(m[11]));
  const title = el({}, unesc(m[5]));
  const g = el({});
  g.dataset = {n: unesc(m[1]), x: m[2], w: m[3], d: m[4]};
  g.style = {};
  g.querySelector = s => s === 'rect' ? rect : s === 'text' ? text : title;
  frames.push(g);
}
const byId = {
  details: el({}, 'base'), matched: el({}, ''), reset: el({}),
  search: el({}),
};
global.document = {
  querySelectorAll: () => frames,
  getElementById: id => byId[id],
  addEventListener: () => {},
};
global.prompt = () => null;
const code = svg.match(/<!\[CDATA\[([\s\S]*?)\]\]>/)[1];
new Function(code + '\nglobalThis.__search = search;')();

const before = frames.map(g => [g.querySelector('rect').getAttribute('x'),
                                g.querySelector('rect').getAttribute('width')]);
const target = frames.find(g => g.dataset.n === process.argv[3]);
target.handlers.click();
const r = target.querySelector('rect');
const zoomed = [Number(r.getAttribute('x')), Number(r.getAttribute('width'))];
const hidden = frames.filter(g => g.style.display === 'none').length;
byId.reset.handlers.click();
const restored = frames.every((g, i) =>
  g.style.display === '' &&
  Math.abs(g.querySelector('rect').getAttribute('x') - before[i][0]) < 0.11 &&
  Math.abs(g.querySelector('rect').getAttribute('width') - before[i][1]) < 0.11);
globalThis.__search(process.argv[4]);
console.log(JSON.stringify({zoomed, hidden, restored,
                            matched: byId.matched.textContent}));
