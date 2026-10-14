// one place decides whether motion is allowed: the os setting or the in-app switch
import { pref } from './dom.js';

const mq = matchMedia('(prefers-reduced-motion: reduce)');
let userReduced = pref.get('reduce-motion', null);
const listeners = new Set();

export const reduced = () => (userReduced === null ? mq.matches : userReduced);
export function setReduced(v) { userReduced = v; pref.set('reduce-motion', v); apply(); }
export const reducedSetting = () => userReduced;
export const onMotionChange = (fn) => { listeners.add(fn); return () => listeners.delete(fn); };
function apply() {
  document.documentElement.dataset.motion = reduced() ? 'reduced' : 'full';
  listeners.forEach((f) => f(reduced()));
}
mq.addEventListener('change', apply);
apply();

// route change: cross-fade through the view transition api when available
export async function transition(update) {
  if (reduced() || !document.startViewTransition) return update();
  try { await document.startViewTransition(update).updateCallbackDone; } catch { /* a skipped transition still ran update */ }
}
export function stagger(parent, sel = ':scope > *', max = 8) {
  if (reduced()) return;
  [...parent.querySelectorAll(sel)].slice(0, max).forEach((el, i) => { el.classList.add('enter'); el.style.setProperty('--i', i); });
}
// animate a number toward a new value without blocking input
export function tween(el, to, fmt = (v) => String(Math.round(v)), ms = 450) {
  const from = Number(el.dataset.v ?? to);
  el.dataset.v = to;
  if (reduced() || from === to || !isFinite(from)) { el.textContent = fmt(to); return; }
  const t0 = performance.now();
  const step = (t) => {
    const k = Math.min(1, (t - t0) / ms), e = 1 - Math.pow(1 - k, 3);
    el.textContent = fmt(from + (to - from) * e);
    if (k < 1 && el.isConnected) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}
