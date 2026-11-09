// Line icons, drawn on a 24px grid. icon('lock') returns an <svg> element.

import { s } from './dom.js';

const PATHS = {
  grid: 'M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z',
  lock: 'M6 11h12v9H6zM8 11V8a4 4 0 0 1 8 0v3',
  check: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM8 12l3 3 5-6',
  file: 'M7 3h7l5 5v13H7zM14 3v5h5',
  flask: 'M9 3h6M10 3v6l-5 9a2 2 0 0 0 2 3h10a2 2 0 0 0 2-3l-5-9V3M7.5 14h9',
  key: 'M8 10a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM12 14h9M17 14v3M21 14v3',
  tests: 'M4 7l2 2 3-3M11 8h9M4 15l2 2 3-3M11 16h9',
  code: 'M8 7l-5 5 5 5M16 7l5 5-5 5',
  search: 'M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM20 20l-4-4',
  home: 'M3 11l9-7 9 7M5 10v10h14V10',
  shield: 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6zM9 12l2 2 4-4',
  download: 'M12 4v11M7 10l5 5 5-5M5 20h14',
  copy: 'M9 9h11v11H9zM5 15V4h11',
  eye: 'M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12zM12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z',
  menu: 'M4 7h16M4 12h16M4 17h16',
  close: 'M6 6l12 12M18 6 6 18',
  plus: 'M12 5v14M5 12h14',
  layers: 'M12 3l9 5-9 5-9-5zM3 13l9 5 9-5',
  tree: 'M10 3h4v4h-4zM3 17h4v4H3zM17 17h4v4h-4zM12 7v5M5 17v-5h14v5',
  pen: 'M4 20h4L19 9l-4-4L4 16zM14 6l4 4',
  alert: 'M12 3l10 18H2zM12 10v5M12 18h.01',
  bolt: 'M13 2 4 14h7l-1 8 9-12h-7z',
  refresh: 'M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7',
};

export function icon(name, cls = 'ic') {
  return s('svg', { class: cls, viewBox: '0 0 24 24', 'aria-hidden': 'true' }, s('path', { d: PATHS[name] }));
}
