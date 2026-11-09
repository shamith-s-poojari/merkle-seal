// A donut chart of file statuses, with a legend.

import { h, s } from './dom.js';

const R = 70, STROKE = 18, GAP = 0.025;   // GAP is a fraction of the ring between segments
const C = 2 * Math.PI * R;

/**
 * segments: [{ key, label, value }]. Empty segments are skipped. `centre` is the big
 * figure in the middle and `caption` the line under it.
 */
export function donut(segments, { centre, caption }) {
  const shown = segments.filter(x => x.value > 0);
  const total = shown.reduce((n, x) => n + x.value, 0) || 1;
  const gap = shown.length > 1 ? GAP : 0;

  let at = 0;
  const arcs = shown.map(seg => {
    const frac = seg.value / total;
    const len = Math.max(frac - gap, 0.004) * C;
    const arc = s('circle', {
      class: `arc arc-${seg.key}`, r: R, cx: 100, cy: 100,
      'stroke-dasharray': `${len} ${C - len}`,
      // Start at twelve o'clock and run clockwise.
      'stroke-dashoffset': String(C / 4 - at * C),
      'stroke-width': STROKE,
    }, s('title', null, `${seg.label}: ${seg.value}`));
    at += frac;
    return arc;
  });

  return h('div', { class: 'donut' },
    s('svg', { viewBox: '0 0 200 200', class: 'donut-svg', role: 'img', 'aria-label': shown.map(x => `${x.label} ${x.value}`).join(', ') },
      s('circle', { class: 'track', r: R, cx: 100, cy: 100, 'stroke-width': STROKE }),
      arcs,
      s('text', { class: 'donut-centre', x: 100, y: 100, 'text-anchor': 'middle', 'dominant-baseline': 'middle' }, centre),
      s('text', { class: 'donut-caption', x: 100, y: 126, 'text-anchor': 'middle' }, caption)),
    h('ul', { class: 'donut-legend' }, shown.map(seg => h('li', null,
      h('i', { class: `sw sw-${seg.key}` }), h('span', null, seg.label),
      h('b', null, `${seg.value} · ${Math.round(100 * seg.value / total)}%`)))));
}
