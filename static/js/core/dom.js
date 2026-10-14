// dom builders. nothing here assigns innerHTML, so server data can never inject markup
export function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  setAttrs(el, attrs);
  append(el, kids);
  return el;
}
export function svg(tag, attrs, ...kids) {
  const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'style') cssText(el, v); else el.setAttribute(k, v);
  }
  append(el, kids);
  return el;
}
function setAttrs(el, attrs) {
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'style') cssText(el, v);
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else if (v === true) el.setAttribute(k, '');
    else el.setAttribute(k, v);
  }
}
// the csp forbids style attributes, so declarations go through the cssom
export function cssText(el, text) {
  for (const decl of String(text).split(';')) {
    const i = decl.indexOf(':');
    if (i > 0) el.style.setProperty(decl.slice(0, i).trim(), decl.slice(i + 1).trim());
  }
}
function append(el, kids) {
  for (const k of kids.flat(Infinity)) {
    if (k == null || k === false) continue;
    el.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
}
export const put = (el, ...kids) => { append(el, kids); return el; };
export const clear = (el) => { while (el.firstChild) el.removeChild(el.firstChild); return el; };
export const $ = (sel, root = document) => root.querySelector(sel);
export function listen(target, type, fn, opts) {
  target.addEventListener(type, fn, opts);
  return () => target.removeEventListener(type, fn, opts);
}
// collects teardown callbacks so a view can release everything it created
export function scope() {
  const fns = [];
  return { add(fn) { if (fn) fns.push(fn); return fn; }, on(t, ty, f, o) { fns.push(listen(t, ty, f, o)); }, dispose() { while (fns.length) { try { fns.pop()(); } catch { /* teardown must not throw */ } } } };
}
export const debounce = (fn, ms) => { let t; const d = (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; d.cancel = () => clearTimeout(t); return d; };
export const pref = {
  get(k, d) { try { const v = localStorage.getItem(`blockaudit.${k}`); return v == null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem(`blockaudit.${k}`, JSON.stringify(v)); } catch { /* storage unavailable */ } },
};
export const sess = {
  get(k, d) { try { const v = sessionStorage.getItem(`blockaudit.${k}`); return v == null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { sessionStorage.setItem(`blockaudit.${k}`, JSON.stringify(v)); } catch { /* storage unavailable */ } },
};
