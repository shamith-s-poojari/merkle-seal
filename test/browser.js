// Runs the shared cases in the browser and lists the results on tests.html.
import { cases } from './cases.js';

const list = document.getElementById('list');
const sum = document.getElementById('sum');
let pass = 0, fail = 0;

for (const { name, fn } of cases) {
  const li = document.createElement('li');
  li.textContent = name;
  try {
    await fn();
    li.className = 'pass';
    pass++;
  } catch (err) {
    li.className = 'fail';
    const why = document.createElement('span');
    why.className = 'why';
    why.textContent = err.message;
    li.append(why);
    fail++;
  }
  list.append(li);
}

sum.textContent = `${pass} passed, ${fail} failed`;
sum.classList.add(fail ? 'bad' : 'ok');
