// Builds shirudo-field-trip.html: a picture-book cutaway of shirudo.
// Every name, path, hook and number drawn comes from the shirudo docs.
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const OUT = join(here, 'shirudo-field-trip.html');

/* ---------- drawing helpers (inline styles so <use> clones keep them) ---------- */
const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const n1 = v => Math.round(v * 10) / 10;
const fl = c => (c === 'none' ? 'fill:none' : `fill:var(--${c})`);
const SK = w => `stroke:var(--line);stroke-width:${w};stroke-linejoin:round;stroke-linecap:round`;
const sty = (c, o) => {
	const w = o.w ?? (o.thin ? 2 : 3);
	return [fl(c), o.nostroke ? '' : SK(w), o.style ?? ''].filter(Boolean).join(';');
};
const R = (x, y, w, h, c, o = {}) =>
	`<rect x="${n1(x)}" y="${n1(y)}" width="${n1(w)}" height="${n1(h)}" rx="${o.rx ?? 6}" style="${sty(c, o)}"${o.attr ? ' ' + o.attr : ''}/>`;
const C = (cx, cy, r, c, o = {}) =>
	`<circle cx="${n1(cx)}" cy="${n1(cy)}" r="${n1(r)}" style="${sty(c, o)}"${o.attr ? ' ' + o.attr : ''}/>`;
const E = (cx, cy, rx, ry, c, o = {}) =>
	`<ellipse cx="${n1(cx)}" cy="${n1(cy)}" rx="${n1(rx)}" ry="${n1(ry)}" style="${sty(c, o)}"${o.attr ? ' ' + o.attr : ''}/>`;
const P = (d, c, o = {}) => `<path d="${d}" style="${sty(c, o)}"${o.attr ? ' ' + o.attr : ''}/>`;
const S = (d, color, w, o = {}) =>
	`<path d="${d}" style="fill:none;stroke:var(--${color});stroke-width:${w};stroke-linecap:round;stroke-linejoin:round${o.style ? ';' + o.style : ''}"${o.attr ? ' ' + o.attr : ''}/>`;
const FONT = { mono: 'var(--f-mono)', disp: 'var(--f-disp)', hand: 'var(--f-hand)' };
const T = (x, y, s, o = {}) => {
	const kind = o.kind ?? 'hand';
	const st = [`font-family:${FONT[kind]}`, `fill:var(--${o.c ?? 'ink'})`, kind === 'mono' ? 'font-weight:600' : '', kind === 'disp' ? 'letter-spacing:.04em' : '', o.style ?? '']
		.filter(Boolean).join(';');
	return `<text x="${n1(x)}" y="${n1(y)}" font-size="${o.size ?? 16}" text-anchor="${o.anchor ?? 'middle'}" style="${st}"${o.attr ? ' ' + o.attr : ''}>${esc(s)}</text>`;
};
const KW = { mono: 0.6, disp: 0.62, hand: 0.45 };
const tw = (s, size, kind) => s.length * size * KW[kind];
function tag(x, y, s, o = {}) {
	const size = o.size ?? 13, kind = o.kind ?? 'mono';
	const w = Math.round(tw(s, size, kind) + (o.pad ?? 14)), h = Math.round(size + 11);
	const x0 = o.anchor === 'start' ? x : o.anchor === 'end' ? x - w : x - w / 2;
	return R(x0, y - h / 2, w, h, o.c ?? 'plate', { rx: o.rx ?? 7, thin: true }) +
		T(x0 + w / 2, y + size * 0.36, s, { size, kind, c: o.ink ?? 'ink' });
}
function bubble(x, y, w, lines, tx, ty, o = {}) {
	const size = o.size ?? 15, lh = size * 1.18, h = Math.round(lines.length * lh + 14);
	const cl = (v, a, b) => Math.max(a, Math.min(b, v));
	let b1, b2;
	if (ty >= y + h) { const bx = cl(tx, x + 24, x + w - 24); b1 = [bx - 9, y + h]; b2 = [bx + 9, y + h]; }
	else if (ty <= y) { const bx = cl(tx, x + 24, x + w - 24); b1 = [bx - 9, y]; b2 = [bx + 9, y]; }
	else if (tx < x) { const by = cl(ty, y + 15, y + h - 15); b1 = [x, by - 8]; b2 = [x, by + 8]; }
	else { const by = cl(ty, y + 15, y + h - 15); b1 = [x + w, by - 8]; b2 = [x + w, by + 8]; }
	const tail = `M${n1(b1[0])} ${n1(b1[1])} L${tx} ${ty} L${n1(b2[0])} ${n1(b2[1])} Z`;
	const dx = b2[0] - b1[0], dy = b2[1] - b1[1], len = Math.hypot(dx, dy), ux = dx / len, uy = dy / len;
	let s = '<g>' + P(tail, 'plate') + R(x, y, w, h, 'plate', { rx: 16 }) +
		`<line x1="${n1(b1[0] + ux * 2.4)}" y1="${n1(b1[1] + uy * 2.4)}" x2="${n1(b2[0] - ux * 2.4)}" y2="${n1(b2[1] - uy * 2.4)}" style="stroke:var(--plate);stroke-width:5"/>`;
	lines.forEach((ln, i) => { s += T(x + w / 2, y + 7 + lh * (i + 0.8), ln, { size, kind: 'hand' }); });
	return s + '</g>';
}
const mark = (x, y, n) => `<g>${C(x, y, 16, 'sun')}${T(x, y + 7, n, { size: 19, kind: 'disp' })}</g>`;
function face(cx, cy, s = 1, mood = 'smile') {
	let f = C(cx - 6 * s, cy, 2.3 * s, 'line', { nostroke: true }) + C(cx + 6 * s, cy, 2.3 * s, 'line', { nostroke: true });
	f += C(cx - 10 * s, cy + 5 * s, 3 * s, 'pink', { nostroke: true, style: 'opacity:.45' }) + C(cx + 10 * s, cy + 5 * s, 3 * s, 'pink', { nostroke: true, style: 'opacity:.45' });
	if (mood === 'smile') f += S(`M${n1(cx - 5 * s)} ${n1(cy + 5 * s)} Q${cx} ${n1(cy + 10 * s)} ${n1(cx + 5 * s)} ${n1(cy + 5 * s)}`, 'line', 2);
	else if (mood === 'o') f += E(cx, cy + 7 * s, 2.4 * s, 3 * s, 'line', { nostroke: true });
	else f += S(`M${n1(cx - 5 * s)} ${n1(cy + 9 * s)} Q${cx} ${n1(cy + 4 * s)} ${n1(cx + 5 * s)} ${n1(cy + 9 * s)}`, 'line', 2);
	return f;
}
function cloud(cx, cy, s, c = 'cloud') {
	const puffs = [[-62, 8, 30], [-30, -14, 36], [12, -22, 42], [54, -4, 34], [80, 14, 24], [30, 16, 30], [-14, 18, 30], [-50, 20, 24]];
	const ps = puffs.map(([x, y, r]) => [cx + x * s, cy + y * s, r * s]);
	return '<g>' + ps.map(([x, y, r]) => C(x, y, r, c, { w: 6 })).join('') + ps.map(([x, y, r]) => C(x, y, r, c, { nostroke: true })).join('') + '</g>';
}
function gear(cx, cy, r, n, c, o = {}) {
	let d = '';
	for (let i = 0; i < n; i++) {
		const a0 = (i / n) * Math.PI * 2, a1 = ((i + 0.25) / n) * Math.PI * 2, a2 = ((i + 0.5) / n) * Math.PI * 2, a3 = ((i + 0.75) / n) * Math.PI * 2;
		const ro = r, ri = r * 0.78;
		const pt = (a, rr) => `${n1(cx + Math.cos(a) * rr)} ${n1(cy + Math.sin(a) * rr)}`;
		d += (i === 0 ? 'M' : 'L') + pt(a0, ri) + ' L' + pt(a1, ro) + ' L' + pt(a2, ro) + ' L' + pt(a3, ri) + ' ';
	}
	return P(d + 'Z', c, o) + C(cx, cy, r * 0.3, o.hub ?? 'plate', { thin: true });
}
function ratchet(cx, cy, r, n, c) {
	let d = '';
	for (let i = 0; i < n; i++) {
		const a0 = (i / n) * Math.PI * 2, a1 = ((i + 1) / n) * Math.PI * 2;
		const pt = (a, rr) => `${n1(cx + Math.cos(a) * rr)} ${n1(cy + Math.sin(a) * rr)}`;
		d += (i === 0 ? 'M' : 'L') + pt(a0, r * 0.8) + ' L' + pt(a1 - 0.02, r) + ' L' + pt(a1, r * 0.8) + ' ';
	}
	return P(d + 'Z', c);
}
function tube(d, o = {}) {
	const w = o.w ?? 20;
	return '<g>' + S(d, 'line', w + 6) + S(d, o.c ?? 'glass', w) + S(d, 'plate', 3, { style: 'opacity:.75', attr: 'transform="translate(-4 -4)"' }) + '</g>';
}
function clock(cx, cy, r) {
	return C(cx - r * 0.62, cy - r * 0.9, r * 0.36, 'sun', { thin: true }) + C(cx + r * 0.62, cy - r * 0.9, r * 0.36, 'sun', { thin: true }) +
		C(cx, cy, r, 'plate') + S(`M${cx} ${n1(cy - r * 0.62)} L${cx} ${cy} L${n1(cx + r * 0.45)} ${n1(cy + r * 0.2)}`, 'line', 2) +
		S(`M${n1(cx - r * 0.6)} ${n1(cy + r * 0.85)} L${n1(cx - r * 0.85)} ${n1(cy + r * 1.15)} M${n1(cx + r * 0.6)} ${n1(cy + r * 0.85)} L${n1(cx + r * 0.85)} ${n1(cy + r * 1.15)}`, 'line', 3);
}
const shield = (x, y, c = 'blue') =>
	P(`M${x} ${y - 8} H${x + 14} V${y - 1} Q${x + 14} ${y + 7} ${x + 7} ${y + 10} Q${x} ${y + 7} ${x} ${y - 1} Z`, c, { thin: true });
const rules = (x, y, w, n, gap, c = 'rule') => Array.from({ length: n }, (_, i) => S(`M${x} ${y + i * gap} H${x + w}`, c, 1.6)).join('');
const podAt = (x, y, s = 1, extra = '') => `<use href="#pod" transform="translate(${x} ${y}) scale(${s})"${extra}/>`;

/* ---------- the scene ---------- */
const parts = [];
const add = (...s) => parts.push(...s);

// sky, sun, decorative clouds
add(`<rect x="0" y="0" width="1600" height="716" style="fill:url(#skyg)"/>`);
add(Array.from({ length: 12 }, (_, i) => {
	const a = (i * Math.PI) / 6;
	return S(`M${n1(1534 + Math.cos(a) * 46)} ${n1(66 + Math.sin(a) * 46)} L${n1(1534 + Math.cos(a) * 60)} ${n1(66 + Math.sin(a) * 60)}`, 'sun-d', 6);
}).join(''));
add(C(1534, 66, 34, 'sun'), face(1534, 62, 1.3));
add(cloud(560, 42, 0.42), cloud(1240, 360, 0.36));

// operator hill
add(P('M0 716 L0 452 Q4 438 40 438 L440 438 Q496 438 508 520 L514 716 Z', 'grass', { nostroke: true }));
add(S('M0 452 Q4 438 40 438 L440 438 Q496 438 508 520', 'grass-d', 5));
for (const [x, y, c] of [[150, 690, 'pink'], [212, 668, 'sun'], [280, 694, 'purple'], [446, 640, 'pink'], [470, 690, 'sun'], [110, 650, 'sun']]) {
	add(S(`M${x} ${y} L${x} ${y + 18}`, 'grass-d', 3));
	for (let k = 0; k < 5; k++) { const a = (k / 5) * Math.PI * 2; add(C(x + Math.cos(a) * 5, y + Math.sin(a) * 5, 4.2, c, { thin: true })); }
	add(C(x, y, 3.2, 'sun-d', { nostroke: true }));
}
// signpost: the operator keeps no state about targets
add(R(377, 562, 9, 128, 'wood', { rx: 3 }));
add(R(302, 520, 160, 50, 'wood-l', { rx: 6 }));
add(T(382, 541, 'operator keeps', { size: 16 }), T(382, 560, 'no target state', { size: 16 }));

// ---- workshop (operator host)
add(R(20, 200, 480, 238, 'op-wall', { rx: 4 }));
add(R(34, 214, 452, 218, 'op-room', { rx: 3, thin: true }));
add(P('M6 208 L260 128 L514 208 Z', 'roof'));
add(S('M60 192 L260 140 L460 192', 'roof-d', 3, { style: 'opacity:.55' }));
add(tag(260, 184, 'OPERATOR', { kind: 'disp', size: 22, c: 'sun' }));
add(R(34, 424, 452, 8, 'wood', { rx: 2, thin: true }));
// verify desk, monitor, mailbox
add(R(42, 370, 98, 54, 'wood', { rx: 4 }));
add(S('M46 390 H136', 'line', 2), C(91, 381, 2.6, 'line', { nostroke: true }));
add(tag(91, 407, 'attest verify', { size: 10 }));
add(R(58, 302, 66, 56, 'line', { rx: 6 }), R(63, 307, 56, 40, 'screen', { rx: 3, nostroke: true }));
add(T(91, 323, 'verify', { size: 11, kind: 'mono', c: 'scr' }), T(91, 341, '✓', { size: 16, kind: 'mono', c: 'scr' }));
add(R(85, 358, 12, 12, 'steel', { rx: 2, thin: true }));
add(R(38, 232, 40, 36, 'red', { rx: 6 }), R(46, 246, 24, 5, 'line', { rx: 2, nostroke: true }), R(70, 226, 4, 16, 'sun', { rx: 1, thin: true }));
// clang machine
add(R(160, 222, 64, 36, 'plate', { rx: 4 }), rules(166, 232, 52, 3, 7, 'rule'), T(192, 254, '*.bpf.c', { size: 10.5, kind: 'mono' }));
add(P('M150 262 L234 262 L222 280 L162 280 Z', 'sun'));
add(R(150, 280, 86, 118, 'blue', { rx: 8 }));
add(C(174, 304, 11, 'plate', { thin: true }), S('M174 304 L181 297', 'line', 2.4));
add(C(206, 300, 4.5, 'green', { thin: true }), C(222, 300, 4.5, 'red', { thin: true }));
add(R(157, 322, 72, 42, 'plate', { rx: 4, thin: true }), T(193, 339, 'clang 23', { size: 11, kind: 'mono' }), T(193, 356, '-mcpu=v4', { size: 11, kind: 'mono' }));
add(S('M160 376 H226 M160 384 H226', 'line', 2, { style: 'opacity:.45' }));
// conveyor belt
add(R(146, 398, 322, 14, 'line', { rx: 7, nostroke: true }));
for (let x = 156; x <= 458; x += 22) add(C(x, 405, 4.2, 'steel', { nostroke: true }));
for (const x of [160, 300, 440]) add(R(x, 412, 7, 12, 'steel-d', { rx: 2, thin: true }));
// gen_loader
add(R(242, 330, 58, 68, 'teal', { rx: 6 }));
add(R(245, 338, 52, 18, 'plate', { rx: 3, thin: true }), T(271, 351, 'gen_loader', { size: 8.5, kind: 'mono' }));
add(gear(271, 378, 11, 8, 'sun', { thin: true }));
// stamp press (signs with the key)
add(R(306, 250, 8, 148, 'steel', { rx: 2 }), R(344, 250, 8, 148, 'steel', { rx: 2 }));
add(R(300, 240, 58, 16, 'steel-d', { rx: 4 }));
add(R(322, 256, 14, 50, 'steel', { rx: 2, thin: true }), R(312, 304, 34, 14, 'pink', { rx: 3 }));
add(tag(329, 226, 'ML-DSA-87', { size: 10 }));
add(S('M394 296 Q390 322 368 306 Q352 292 338 268', 'line', 7), S('M394 296 Q390 322 368 306 Q352 292 338 268', 'purple', 3.5));
// safe with the private key, on a shelf
add(R(380, 234, 66, 62, 'steel', { rx: 6 }), R(386, 240, 54, 50, 'steel-l', { rx: 4, thin: true }));
add(C(403, 265, 9, 'plate', { thin: true }), S('M403 265 L403 258', 'line', 2));
for (let k = 0; k < 8; k++) { const a = (k / 8) * Math.PI * 2; add(C(403 + Math.cos(a) * 12.5, 265 + Math.sin(a) * 12.5, 1.3, 'line', { nostroke: true })); }
add(R(424, 254, 6, 22, 'line', { rx: 3, nostroke: true }));
add(R(372, 296, 82, 7, 'wood', { rx: 2, thin: true }), P('M380 303 L380 318 L394 303 Z', 'wood', { thin: true }), P('M446 303 L446 318 L432 303 Z', 'wood', { thin: true }));
add(tag(404, 322, 'signing_key.pem', { size: 9.5 }));

// ---- registry island
add(cloud(770, 266, 1.55), cloud(1010, 270, 1.45));
add(R(690, 86, 270, 154, 'blue-l', { rx: 4 }));
add(R(702, 98, 246, 136, 'room2', { rx: 2, thin: true }));
add(P('M680 92 L825 50 L970 92 Z', 'blue'));
add(tag(825, 74, 'OCI REGISTRY', { kind: 'disp', size: 18, c: 'sun' }));
for (const y of [140, 180, 220]) add(R(706, y, 238, 6, 'wood', { rx: 2, thin: true }));
const box = (x, y, w, c, label) => R(x, y - 28, w, 28, c, { rx: 3 }) + R(x + 5, y - 21, w - 10, 14, 'plate', { rx: 2, thin: true }) + T(x + w / 2, y - 10.5, label, { size: 9, kind: 'mono' });
add(box(710, 140, 72, 'teal', 'kernel-obs'), box(786, 140, 74, 'pink', 'app-sandbox'), box(864, 140, 72, 'purple', 'kernel-cve'));
add(box(710, 180, 74, 'orange-l', 'java-base64'), box(788, 180, 78, 'sun', 'java-sql-inj'), box(870, 180, 50, 'green', 'test'));
add(R(836, 192, 104, 28, 'plate', { rx: 3 }), rules(844, 201, 70, 2, 7), C(926, 206, 6, 'pink', { thin: true }));
add(T(880, 216, 'index (signed)', { size: 9, kind: 'mono' }));
add(tag(752, 208, '.bee pkgs', { size: 9 }));
// upatch tree: append-only signed list of operations
add(P('M1052 262 L1058 198 L1050 162 L1066 162 L1070 198 L1078 262 Z', 'wood'));
const canopy = [[1026, 140, 28], [1064, 116, 34], [1102, 140, 28], [1064, 158, 26], [1040, 164, 20], [1090, 164, 20]];
add(canopy.map(([x, y, r]) => C(x, y, r, 'grass', { w: 6 })).join('') + canopy.map(([x, y, r]) => C(x, y, r, 'grass', { nostroke: true })).join(''));
add(S('M1008 168 L1008 182 M1120 168 L1120 182', 'line', 2));
add(tag(1008, 192, '#1 add', { size: 9.5, c: 'sun' }), tag(1064, 222, '#2 add', { size: 9.5, c: 'sun' }), tag(1120, 192, '#3 del', { size: 9.5, c: 'pink-l' }));
add(C(1046, 222, 1.8, 'line', { nostroke: true }), C(1082, 222, 1.8, 'line', { nostroke: true }));
add(tag(1064, 284, 'upatch tree', { size: 11 }));

// ---- collector (target pushes telemetry, nothing pushes to the target)
add(cloud(1372, 236, 1.0));
add(S('M1372 196 L1372 214', 'line', 5), R(1352, 212, 40, 12, 'steel', { rx: 3, thin: true }));
add(E(1372, 186, 30, 13, 'plate', { attr: 'transform="rotate(-28 1372 186)"' }));
add(S('M1372 186 L1392 166', 'line', 2.5), C(1394, 164, 4, 'red', { thin: true }));
add(tag(1372, 248, 'OTLP collector', { size: 11 }));

// ---- route (dotted guide; hidden behind whatever it passes)
const ROUTE = 'M410 380 L468 380 L468 150 Q468 108 510 108 L652 108 Q694 108 700 150 L780 200 L820 238 L820 286 Q820 344 762 348 L618 352 L575 352 L575 652 Q575 620 607 620 L720 620 L800 620 Q852 620 852 664 L852 760 Q852 800 800 840 Q760 872 722 902 L784 902 L1051 852 L1470 914';
const WIRE = 'M1470 972 L1470 1008 L476 1008 L476 1030';
const EVID = 'M160 1171 L13 1171 L13 250 L46 250';

// ---- tubes: push (operator to registry) and pull (registry to target)
add(tube('M468 398 L468 150 Q468 108 510 108 L652 108 Q694 108 700 150'));
for (const [x, y, w, h] of [[456, 300, 24, 6], [456, 200, 24, 6], [580, 96, 6, 24]]) add(R(x, y, w, h, 'steel-d', { rx: 2, thin: true }));
add(tag(580, 82, 'bpm push · bpm tree append', { size: 11 }));
add(tube('M820 238 L820 286 Q820 344 762 348 L618 352'));
add(R(808, 270, 24, 6, 'steel-d', { rx: 2, thin: true }), R(700, 338, 6, 24, 'steel-d', { rx: 2, thin: true }));
add(tag(708, 316, 'repo update · upgrade · tree sync', { size: 9 }));

// ---- target house (userspace)
add(R(520, 392, 1064, 308, 'house', { rx: 4 }));
add(R(534, 406, 1036, 288, 'room', { rx: 3, thin: true }));
add(`<path d="${ROUTE}" style="fill:none;stroke:var(--route);stroke-width:4;stroke-linecap:round;stroke-dasharray:1 12;opacity:.9" id="route-path"/>`);
add(R(508, 374, 1088, 20, 'roof', { rx: 4 }));
add(T(1366, 388, 'no daemon · no listening socket · nothing connects in', { size: 11, kind: 'mono' }));
add(tag(720, 384, 'USERSPACE', { kind: 'disp', size: 14 }));
add(S('M990 342 L990 374 M1110 342 L1110 374', 'line', 5));
add(tag(1050, 332, 'TARGET HOST', { kind: 'disp', size: 24, c: 'sun' }));
// roof pump driven by systemd timers
add(R(536, 326, 78, 48, 'steel', { rx: 10 }), C(575, 350, 15, 'plate', { thin: true }));
for (let k = 0; k < 3; k++) { const a = (k / 3) * Math.PI * 2 - 0.4; add(P(`M575 350 Q${n1(575 + Math.cos(a) * 14)} ${n1(350 + Math.sin(a) * 4)} ${n1(575 + Math.cos(a + 0.7) * 13)} ${n1(350 + Math.sin(a + 0.7) * 13)} Z`, 'steel-d', { thin: true })); }
add(C(575, 350, 3.5, 'line', { nostroke: true }));
add(clock(552, 314, 10), clock(575, 314, 10), clock(598, 314, 10));
add(tag(575, 280, 'systemd timers', { size: 11 }));
// antenna for telemetry
add(S('M1546 374 L1546 316', 'line', 5), C(1546, 312, 6, 'red'));
add(S('M1530 300 Q1546 284 1562 300 M1520 290 Q1546 264 1572 290', 'teal', 3));
add(S('M1534 296 L1400 170', 'teal', 3, { style: 'stroke-dasharray:6 9' }));
add(tag(1500, 200, 'status · maps', { size: 10 }));
// hoist shaft
add(R(548, 406, 52, 288, 'shaft', { rx: 0, nostroke: true }));
add(S('M552 406 L552 694 M596 406 L596 694', 'steel-d', 4));
for (let y = 430; y < 690; y += 36) add(S(`M552 ${y} L596 ${y + 18}`, 'steel-d', 2, { style: 'opacity:.6' }));
// floors
add(R(604, 540, 966, 12, 'wood', { rx: 2, thin: true }), R(534, 540, 14, 12, 'wood', { rx: 2, thin: true }));
add(R(534, 688, 278, 8, 'wood', { rx: 2, thin: true }), R(892, 688, 678, 8, 'wood', { rx: 2, thin: true }));

// upper story: runtime image, config image, Java corner, telemetry desk
function glassCase(x, label, inner) {
	return R(x + 2, 436, 156, 98, 'glass', { rx: 6 }) + inner + R(x - 4, 428, 168, 12, 'steel', { rx: 4 }) +
		S(`M${x + 72} 424 Q${x + 80} 412 ${x + 88} 424`, 'line', 3) + R(x + 70, 422, 20, 13, 'sun', { rx: 3, thin: true }) +
		S(`M${x + 12} 446 L${x + 26} 446`, 'plate', 3, { style: 'opacity:.8' }) + tag(x + 80, 522, label, { size: 10.5 });
}
add(glassCase(620, 'runtime image',
	R(636, 452, 40, 46, 'teal', { rx: 6, thin: true }) + gear(656, 475, 11, 7, 'sun', { thin: true }) +
	R(684, 452, 40, 30, 'plate', { rx: 3, thin: true }) + rules(690, 461, 22, 2, 7) + C(714, 474, 5, 'pink', { thin: true }) +
	R(730, 452, 36, 46, 'plate', { rx: 2, thin: true }) + rules(736, 462, 24, 4, 8)));
add(T(702, 507, 'cert.der · shirudo.conf', { size: 8.5, kind: 'mono' }));
add(glassCase(796, 'config image',
	R(810, 452, 34, 42, 'plate', { rx: 2, thin: true }) + rules(815, 461, 24, 4, 8) +
	R(850, 452, 34, 30, 'plate', { rx: 3, thin: true }) + C(872, 470, 5, 'pink', { thin: true }) + rules(855, 460, 14, 2, 7) +
	R(890, 452, 34, 30, 'plate', { rx: 3, thin: true }) + C(912, 470, 5, 'pink', { thin: true }) + S('M894 456 L920 478 M920 456 L894 478', 'red', 3) +
	P('M872 486 L884 498 L860 498 Z', 'grass', { thin: true })));
add(T(876, 507, 'certs · revoked · labels', { size: 8.5, kind: 'mono' }));
// java corner
add(R(978, 470, 72, 6, 'wood', { rx: 2, thin: true }));
for (const x of [994, 1030]) add(R(x - 11, 440, 22, 30, 'glass', { rx: 6 }), R(x - 12, 435, 24, 7, 'orange', { rx: 2, thin: true }), R(x - 7, 452, 14, 9, 'plate', { rx: 1, thin: true }));
add(tag(1014, 492, '/run/shirudo-java', { size: 9.5 }));
add(S('M1050 452 Q1066 430 1086 432', 'line', 2.5, { style: 'stroke-dasharray:4 5' }));
add(R(1076, 438, 128, 94, 'purple', { rx: 12 }));
add(P('M1086 438 L1082 426 L1106 426 L1102 438 Z', 'steel', { thin: true }));
add(R(1088, 450, 62, 36, 'screen', { rx: 4, thin: true }), T(1119, 475, 'JVM', { size: 17, kind: 'disp', c: 'scr' }));
add(C(1176, 458, 7, 'sun', { thin: true }), C(1176, 480, 7, 'teal', { thin: true }));
add(tag(1140, 512, 'Java upatch', { size: 10 }));
// telemetry desk
add(R(1300, 494, 172, 10, 'wood', { rx: 3 }), R(1310, 504, 8, 36, 'wood', { rx: 2, thin: true }), R(1454, 504, 8, 36, 'wood', { rx: 2, thin: true }));
add(R(1318, 474, 70, 20, 'sun', { rx: 3 }));
for (let k = 0; k < 3; k++) add(R(1326 + k * 3, 462 - k * 5, 46, 16, 'plate', { rx: 2, thin: true }), S(`M${1326 + k * 3} ${462 - k * 5} L${1349 + k * 3} ${471 - k * 5} L${1372 + k * 3} ${462 - k * 5}`, 'line', 1.6));
add(R(1406, 462, 46, 32, 'screen', { rx: 4, thin: true }), S('M1414 486 L1424 476 L1432 482 L1444 470', 'scr', 2.4));
add(S('M1452 470 Q1520 460 1540 400', 'line', 3));
add(tag(1386, 430, 'status + map export → OTLP', { size: 10.5 }));

// ground story: workbench + one-shot worker, trapdoor, root, state shelves, eventlog
function robot(x, y) {
	return R(x - 14, y - 24, 10, 24, 'steel-d', { rx: 3, thin: true }) + R(x + 4, y - 24, 10, 24, 'steel-d', { rx: 3, thin: true }) +
		S(`M${x + 18} ${y - 56} Q${x + 40} ${y - 62} ${x + 52} ${y - 70}`, 'line', 10) + S(`M${x + 18} ${y - 56} Q${x + 40} ${y - 62} ${x + 52} ${y - 70}`, 'steel', 5) +
		R(x - 22, y - 72, 44, 50, 'teal', { rx: 10 }) + R(x - 16, y - 60, 32, 14, 'plate', { rx: 3, thin: true }) + T(x, y - 50, 'shirudo', { size: 7, kind: 'mono' }) +
		R(x - 18, y - 104, 36, 30, 'steel', { rx: 9 }) + face(x, y - 92, 0.9) + S(`M${x} ${y - 104} L${x} ${y - 114}`, 'line', 3) + C(x, y - 117, 4, 'red', { thin: true });
}
add(robot(632, 688));
add(R(660, 640, 132, 10, 'wood', { rx: 3 }), R(668, 650, 8, 38, 'wood', { rx: 2, thin: true }), R(776, 650, 8, 38, 'wood', { rx: 2, thin: true }));
add(R(756, 598, 32, 42, 'plate', { rx: 3 }), R(764, 594, 16, 7, 'steel', { rx: 2, thin: true }));
for (let k = 0; k < 3; k++) add(S(`M761 ${610 + k * 10} l3 3 l5 -6`, 'green', 2.4), S(`M772 ${611 + k * 10} H784`, 'line', 1.6));
// trapdoor to bpf()
add(R(812, 686, 80, 12, 'line', { rx: 3, nostroke: true }));
add(P('M812 688 L798 636 L808 632 L822 686 Z', 'wood'));
add(S('M838 552 L838 572 M866 552 L866 572', 'line', 2));
add(tag(852, 584, 'bpf()', { size: 15, c: 'sun' }));
// root, the raccoon, refused at the gate
function raccoon(x, y) {
	let s = P(`M${x + 18} ${y - 26} Q${x + 70} ${y - 30} ${x + 66} ${y - 76} Q${x + 62} ${y - 94} ${x + 48} ${y - 82} Q${x + 52} ${y - 52} ${x + 14} ${y - 42} Z`, 'fur');
	s += S(`M${x + 40} ${y - 32} L${x + 46} ${y - 44} M${x + 56} ${y - 40} L${x + 62} ${y - 50} M${x + 58} ${y - 62} L${x + 66} ${y - 64}`, 'mask', 6);
	s += E(x - 12, y - 4, 11, 5, 'mask') + E(x + 12, y - 4, 11, 5, 'mask');
	s += E(x, y - 36, 26, 32, 'fur') + E(x, y - 30, 15, 20, 'fur-l', { nostroke: true });
	s += P(`M${x - 22} ${y - 102} L${x - 26} ${y - 124} L${x - 6} ${y - 108} Z`, 'fur') + P(`M${x + 22} ${y - 102} L${x + 26} ${y - 124} L${x + 6} ${y - 108} Z`, 'fur');
	s += C(x, y - 86, 25, 'fur');
	s += P(`M${x - 25} ${y - 92} Q${x} ${y - 104} ${x + 25} ${y - 92} Q${x + 21} ${y - 76} ${x + 8} ${y - 81} Q${x} ${y - 85} ${x - 8} ${y - 81} Q${x - 21} ${y - 76} ${x - 25} ${y - 92} Z`, 'mask', { nostroke: true });
	s += C(x - 10, y - 89, 5.5, 'plate', { thin: true }) + C(x + 10, y - 89, 5.5, 'plate', { thin: true }) + C(x - 9, y - 88, 2.4, 'line', { nostroke: true }) + C(x + 11, y - 88, 2.4, 'line', { nostroke: true });
	s += E(x, y - 72, 10, 7, 'fur-l', { thin: true }) + C(x, y - 76, 3, 'line', { nostroke: true }) + S(`M${x - 5} ${y - 66} Q${x} ${y - 70} ${x + 5} ${y - 66}`, 'line', 2);
	s += P(`M${x - 14} ${y - 108} L${x - 14} ${y - 122} L${x - 7} ${y - 114} L${x} ${y - 126} L${x + 7} ${y - 114} L${x + 14} ${y - 122} L${x + 14} ${y - 108} Z`, 'sun');
	s += R(x - 64, y - 70, 42, 30, 'plate', { rx: 3 }) + S(`M${x - 43} ${y - 70} V${y - 40} M${x - 64} ${y - 55} H${x - 22}`, 'pink', 2.5) + T(x - 43, y - 59, 'BPF', { size: 9, kind: 'mono' });
	s += S(`M${x - 18} ${y - 48} Q${x - 24} ${y - 52} ${x - 26} ${y - 56}`, 'line', 9) + S(`M${x - 18} ${y - 48} Q${x - 24} ${y - 52} ${x - 26} ${y - 56}`, 'fur', 5);
	s += tag(x, y - 38, 'root', { size: 10, c: 'sun' });
	s += `<g transform="rotate(-10 ${x - 64} ${y - 22})">` + R(x - 104, y - 33, 80, 22, 'plate', { style: 'stroke:var(--red);stroke-width:3' }) +
		T(x - 64, y - 16, 'REFUSED', { size: 14, kind: 'disp', c: 'red' }) + '</g>';
	return s;
}
add(raccoon(970, 688));
// /var/lib/shirudo shelves (labelled state) and the eventlog
add(R(1180, 566, 210, 122, 'wood-l', { rx: 4 }), R(1176, 560, 218, 10, 'wood', { rx: 3 }));
add(tag(1285, 582, '/var/lib/shirudo', { size: 10.5 }));
add(R(1186, 628, 198, 6, 'wood', { rx: 2, thin: true }));
for (const x of [1214, 1262, 1310, 1358]) add(podAt(x, 614, 0.4), S(`M${x + 8} 606 L${x + 13} 600`, 'line', 1.4), R(x + 11, 594, 12, 8, 'pink', { rx: 2, thin: true }));
add(tag(1285, 648, 'xattr security.bpf.shirudo', { size: 9, c: 'pink-l' }));
for (const [x, w, c, l] of [[1192, 56, 'teal', 'tree'], [1254, 58, 'sun', 'pkgs'], [1318, 60, 'blue-l', 'config']]) add(R(x, 664, w, 22, c, { rx: 3, thin: true }), T(x + w / 2, 679, l, { size: 9, kind: 'mono' }));
add(P('M1470 688 L1478 626 L1494 626 L1502 688 Z', 'wood'));
add(P('M1424 628 L1548 628 L1540 610 L1432 610 Z', 'wood'));
add(P('M1436 608 Q1460 598 1486 606 L1486 626 Q1460 618 1436 626 Z', 'plate', { thin: true }), P('M1486 606 Q1512 598 1536 608 L1536 626 Q1512 618 1486 626 Z', 'plate', { thin: true }));
add(rules(1442, 612, 38, 2, 6), rules(1492, 612, 38, 2, 6));
add(tag(1486, 582, 'eventlog', { size: 11 }));

// ---- earth: kernel chamber
add(R(0, 700, 1600, 16, 'grass', { rx: 0 }));
add(R(0, 716, 1600, 290, 'soil', { rx: 0, nostroke: true }));
for (let i = 0; i < 70; i++) { const x = (i * 233) % 1600, y = 718 + ((i * 97) % 270); add(C(x, y, 2 + (i % 3), 'soil-d', { nostroke: true })); }
add(R(814, 696, 76, 34, 'shaft', { rx: 0 }));
add(R(16, 726, 1568, 262, 'kernel', { rx: 30 }));
add(R(814, 720, 76, 12, 'shaft', { rx: 0, nostroke: true }));
add(tag(118, 752, 'THE KERNEL', { kind: 'disp', size: 17, c: 'purple-l' }));
// guard booth: the embedded LSM programs init attaches
add(R(44, 790, 300, 186, 'blue-l', { rx: 8 }));
for (let i = 0; i < 15; i++) add(C(46 + i * 21, 792, 10.5, i % 2 ? 'plate' : 'blue'));
add(R(36, 774, 316, 18, 'blue', { rx: 4 }));
add(tag(194, 818, 'guards: bpf2 + seal', { size: 11 }));
const hooksA = ['lsm/bpf', 'lsm/bpf_map', 'lsm/bpf_prog', 'lsm/bpf_prog_load', 'lsm/tpm_command'];
const hooksB = ['bprm_check_security', 'ptrace_access_check', 'task_kill', 'mmap_file', 'kexec · lockdown'];
hooksA.forEach((h, i) => add(shield(56, 850 + i * 26), T(76, 854 + i * 26, h, { size: 10, kind: 'mono', anchor: 'start' })));
hooksB.forEach((h, i) => add(shield(196, 850 + i * 26, 'teal'), T(216, 854 + i * 26, h, { size: 10, kind: 'mono', anchor: 'start' })));
// .bpf keyring vault
add(R(520, 770, 52, 36, 'plate', { rx: 3 }), rules(526, 780, 30, 2, 7), C(560, 796, 6, 'pink', { thin: true }));
add(R(358, 786, 206, 170, 'steel', { rx: 18 }));
add(R(352, 816, 10, 22, 'steel-d', { rx: 3, thin: true }), R(352, 896, 10, 22, 'steel-d', { rx: 3, thin: true }));
add(C(461, 866, 62, 'steel-l'), C(461, 866, 48, 'steel', { thin: true }));
for (let k = 0; k < 10; k++) { const a = (k / 10) * Math.PI * 2; add(C(461 + Math.cos(a) * 55, 866 + Math.sin(a) * 55, 3.4, 'steel-d', { thin: true })); }
for (let k = 0; k < 4; k++) { const a = (k / 4) * Math.PI * 2 + Math.PI / 4; add(S(`M${n1(461 + Math.cos(a) * 14)} ${n1(866 + Math.sin(a) * 14)} L${n1(461 + Math.cos(a) * 36)} ${n1(866 + Math.sin(a) * 36)}`, 'line', 6), C(461 + Math.cos(a) * 38, 866 + Math.sin(a) * 38, 5, 'steel-d', { thin: true })); }
add(C(461, 866, 15, 'steel-d', { thin: true }));
add(`<g transform="rotate(-16 461 866)">` + R(396, 852, 130, 28, 'red', { rx: 4 }) + T(461, 873, 'SEALED', { size: 18, kind: 'disp', c: 'plate' }) + '</g>');
add(tag(461, 944, '.bpf keyring', { size: 12 }));
add(tag(461, 972, 'and .dm-verity', { size: 9 }));
// verifier station with the frozen map on its table
add(R(576, 922, 266, 10, 'wood', { rx: 3 }), R(586, 932, 8, 48, 'wood', { rx: 2, thin: true }), R(826, 932, 8, 48, 'wood', { rx: 2, thin: true }));
add(R(598, 860, 64, 32, 'plate', { rx: 3, thin: true }), rules(604, 870, 50, 2, 8), T(630, 888, 'data', { size: 9, kind: 'mono' }));
add(R(590, 846, 80, 76, 'ice', { rx: 6, style: 'fill-opacity:.72' }));
add(P('M590 846 L608 830 L688 830 L670 846 Z', 'ice-l'), P('M670 846 L688 830 L688 906 L670 922 Z', 'ice-d'));
add(S('M598 852 L612 852 M598 858 L606 858 M676 846 L682 840', 'plate', 2.5, { style: 'opacity:.9' }));
add(face(630, 906, 0.8, 'o'));
for (const [x, y] of [[600, 916], [662, 852], [646, 914]]) add(C(x, y, 2, 'plate', { nostroke: true }));
add(tag(628, 954, '__loader.map', { size: 10 }));
add(R(826, 836, 8, 86, 'steel', { rx: 2 }), S('M830 842 L806 856', 'line', 5));
add(C(790, 866, 22, 'glass', { w: 5, style: 'fill-opacity:.55' }), S('M778 856 Q784 850 792 850', 'plate', 3));
add(tag(752, 954, 'bpf_check()', { size: 10 }));
add(C(812, 818, 12, 'green'), S('M806 818 l4 4 l8 -9', 'plate', 3));
add(S('M564 834 C606 812 732 808 772 848', 'line', 9), S('M564 834 C606 812 732 808 772 848', 'purple', 5));
// lsm/bpf guard at the bottom of the gate
add(P('M892 760 H932 V786 Q932 806 912 816 Q892 806 892 786 Z', 'blue'), R(898, 752, 28, 10, 'blue-d', { rx: 4 }), face(912, 782, 0.9));
add(tag(912, 830, 'lsm/bpf', { size: 11 }));
// the loader unpacking its payload
add(R(992, 872, 118, 82, 'purple', { rx: 6 }), R(1043, 872, 16, 82, 'sun', { rx: 0, thin: true }));
add(`<g transform="rotate(-22 992 872)">` + R(986, 856, 130, 18, 'purple-l', { rx: 4 }) + R(1043, 856, 16, 18, 'sun', { rx: 0, thin: true }) + '</g>');
add(gear(1002, 832, 12, 8, 'teal', { thin: true }), gear(1108, 836, 13, 9, 'orange-l', { thin: true }));
add(R(1120, 860, 22, 28, 'teal', { rx: 8 }), S('M1120 868 H1142 M1120 880 H1142', 'line', 2));
add(S('M1000 812 l-6 -10 M1110 812 l6 -10 M1052 828 l0 -12', 'line', 2.4, { style: 'opacity:.6' }));
add(T(1051, 920, 'SYSCALL', { size: 15, kind: 'disp', c: 'plate' }));
add(tag(1051, 970, 'loader runs, kernel = true', { size: 10 }));
add(tag(1120, 800, 'nested bpf() calls', { size: 10 }));
// private bpffs pinboard
add(R(1218, 794, 350, 176, 'cork', { rx: 8 }));
for (let i = 0; i < 46; i++) { const x = 1228 + ((i * 71) % 330), y = 802 + ((i * 53) % 160); add(C(x, y, 1.6, 'cork-d', { nostroke: true })); }
add(tag(1393, 812, '/run/shirudo/bpffs (private)', { size: 11 }));
const card = (x, y, w, label, rot) => `<g transform="rotate(${rot} ${x + w / 2} ${y + 18})">` + R(x, y, w, 36, 'plate', { rx: 3, thin: true }) +
	T(x + w / 2, y + 23, label, { size: 9.5, kind: 'mono' }) + '</g>' + C(x + w / 2, y + 3, 4.5, 'red', { thin: true });
add(card(1236, 836, 92, 'lsm_link', -3), card(1342, 836, 132, 'upatches/<name>/link', 2), card(1488, 836, 64, 'maps/', -2));
add(card(1236, 886, 100, 'serializers/', 2), card(1350, 886, 56, 'test', -3));
add(T(1393, 958, 'attach: lsm · fentry · kprobe · uprobe · xdp', { size: 10, kind: 'mono' }));

// ---- bedrock and the TPM
add(P('M0 1004 Q80 990 160 1002 T320 1000 T480 1004 T640 998 T800 1004 T960 998 T1120 1004 T1280 998 T1440 1004 T1600 1000 L1600 1240 L0 1240 Z', 'rock'));
for (const [x, y, rx, ry] of [[40, 1224, 26, 10], [1540, 1228, 30, 9], [1560, 1060, 18, 9], [60, 1040, 16, 8], [1520, 1150, 12, 7]]) add(E(x, y, rx, ry, 'rock-d', { thin: true }));
for (let x = 140; x <= 1470; x += 30) add(R(x, 1024, 12, 12, 'steel', { rx: 2, thin: true }), R(x, 1212, 12, 12, 'steel', { rx: 2, thin: true }));
add(R(110, 1032, 1390, 184, 'chip', { rx: 16 }), R(122, 1044, 1366, 160, 'chip-l', { rx: 12, nostroke: true, style: 'opacity:.35' }));
add(C(134, 1056, 6, 'chip-d', { nostroke: true }));
add(tag(205, 1064, 'TPM 2.0', { kind: 'disp', size: 16, c: 'sun' }));
// attestation key: a stamp
add(C(252, 1094, 13, 'red'), R(246, 1106, 12, 18, 'wood', { rx: 2, thin: true }), R(216, 1122, 72, 20, 'wood', { rx: 4 }), R(220, 1142, 64, 8, 'pink', { rx: 2, thin: true }));
add(R(140, 1158, 42, 26, 'plate', { rx: 3 }), S('M140 1158 L161 1173 L182 1158', 'line', 2), C(170, 1178, 5, 'pink', { thin: true }));
add(tag(252, 1190, 'attestation key', { size: 10 }));
// the register: a ratchet that only turns forward
add(ratchet(470, 1116, 40, 16, 'sun'), C(470, 1116, 14, 'sun-d', { thin: true }), face(470, 1112, 0.8));
add(P('M500 1074 L520 1060 L526 1066 L510 1082 Z', 'steel', { thin: true }));
add(S('M424 1074 A56 56 0 0 1 468 1062', 'plate', 3), P('M468 1056 L478 1063 L466 1069 Z', 'plate', { nostroke: true }));
add(R(526, 1064, 238, 100, 'plate', { rx: 10 }));
add(T(645, 1088, 'NV index 0x01818E00', { size: 12, kind: 'mono' }));
add(T(645, 1114, 'new = SHA-256(old ‖ event)', { size: 12, kind: 'mono' }));
add(T(645, 1140, 'clears at TPM reset', { size: 12, kind: 'mono' }));
add(tag(590, 1190, 'measurement register', { size: 11 }));
// PCR bank
for (let i = 0; i < 24; i++) {
	const cx = 800 + (i % 8) * 34, cy = 1070 + Math.floor(i / 8) * 30;
	const c = i === 9 || i === 11 ? 'sun' : 'plate';
	add(R(cx, cy, 30, 24, c, { rx: 4, thin: true }));
	if (i === 9) add(R(cx - 3, cy - 3, 36, 30, 'none', { rx: 6, style: 'stroke:var(--pink);stroke-width:3' }));
	add(T(cx + 15, cy + 16.5, String(i), { size: 11, kind: 'mono' }));
}
add(tag(934, 1170, 'PCR 9 + 11: binding', { size: 10 }), tag(934, 1194, 'PCR 9: anchor', { size: 10, c: 'pink-l' }));
// writer key
add(C(1148, 1104, 20, 'sun'), C(1148, 1104, 7, 'chip', { thin: true }), R(1166, 1098, 82, 12, 'sun', { rx: 3 }), R(1224, 1110, 8, 14, 'sun', { rx: 1, thin: true }), R(1238, 1110, 8, 10, 'sun', { rx: 1, thin: true }));
add(tag(1196, 1150, 'writer key', { size: 11 }), tag(1196, 1176, 'made in the TPM at boot', { size: 9.5 }));
// tpm_command guard
add(S('M1385 1096 V1088 A10 10 0 0 1 1405 1088 V1096', 'line', 8), S('M1385 1096 V1088 A10 10 0 0 1 1405 1088 V1096', 'steel-l', 4));
add(R(1377, 1094, 36, 28, 'blue', { rx: 6 }), C(1395, 1105, 4, 'line', { nostroke: true }), R(1393, 1106, 4, 9, 'line', { rx: 1, nostroke: true }));
add(tag(1395, 1150, 'NV_Extend guarded by', { size: 9.5 }), tag(1395, 1176, 'lsm/tpm_command', { size: 9.5 }));

// extend wire: load event to the register
add(S(WIRE, 'line', 10), S(WIRE, 'sun', 5));
add(`<path d="${WIRE}" id="wire-path" style="fill:none;stroke:none"/>`);
add(tag(980, 1008, 'extend: load event, domain-separated tag', { size: 10 }));
// evidence tube: TPM-signed evidence back to the operator
add(tube(EVID, { w: 18, c: 'glass2' }));
add(`<path d="${EVID}" id="evidence-path" style="fill:none;stroke:none"/>`);

// ---- speech bubbles
add(bubble(524, 146, 176, ['Only the operator', 'holds the private key.'], 446, 250));
add(bubble(1104, 26, 176, ['Just storage.', 'Targets come to me.'], 968, 96));
add(bubble(664, 554, 152, ['upatch load: one', 'shot, then exit.'], 650, 588, { size: 14 }));
add(bubble(1010, 560, 156, ['Even CAP_SYS_ADMIN', 'can’t load my BPF?!'], 992, 600));
add(bubble(360, 736, 210, ['Sealed: no new keys this boot.'], 430, 788, { size: 14 }));
add(bubble(584, 736, 196, ['Frozen and exclusive:', 'only my loader binds me.'], 632, 830, { size: 14 }));
add(bubble(948, 734, 192, ['From userspace: filtered.', 'From a signed loader: pass.'], 932, 772, { size: 14 }));
add(bubble(62, 590, 196, ['Signed by the TPM.', 'Checked offline.'], 26, 652));

// ---- stop numbers
const MARKS = { 1: [96, 172], 2: [690, 66], 3: [506, 342], 4: [728, 668], 5: [788, 716], 6: [584, 846], 7: [854, 878], 8: [968, 864], 9: [440, 1008], 10: [52, 474] };
for (const [k, [x, y]] of Object.entries(MARKS)) add(mark(x, y, k));

/* ---------- defs ---------- */
const POD = `<g id="pod">
<rect x="-34" y="-19" width="68" height="38" rx="19" style="fill:var(--orange);${SK(3)}"/>
<rect x="-6" y="-19" width="12" height="38" style="fill:var(--sun);${SK(2)}"/>
<circle cx="-18" cy="-1" r="9" style="fill:var(--glass);${SK(2)}"/>
<path d="M-23 -4 h9 M-23 0 h6 M-23 4 h8" style="fill:none;stroke:var(--line);stroke-width:1.6;stroke-linecap:round"/>
<circle cx="19" cy="0" r="9.5" style="fill:var(--pink);${SK(2)}"/>
<path d="M14.6 0.4 l3.2 3.2 l6 -7" style="fill:none;stroke:var(--plate);stroke-width:2.6;stroke-linecap:round;stroke-linejoin:round"/>
<path d="M-26 -12 Q-15 -16.5 -8 -16" style="fill:none;stroke:var(--plate);stroke-width:3;stroke-linecap:round;opacity:.7"/>
</g>`;
const SPARK = `<g id="spark">${P('M0 -16 L4 -5 L16 -5 L6 2 L10 14 L0 7 L-10 14 L-6 2 L-16 -5 L-4 -5 Z', 'sun')}</g>`;
const ENV = `<g id="env">${R(-20, -13, 40, 26, 'plate', { rx: 3 })}${S('M-20 -13 L0 2 L20 -13', 'line', 2)}${C(10, 7, 5, 'pink', { thin: true })}</g>`;
const DEFS = `<defs>
<linearGradient id="skyg" x1="0" y1="0" x2="0" y2="1"><stop offset="0" style="stop-color:var(--sky)"/><stop offset="1" style="stop-color:var(--sky2)"/></linearGradient>
${POD}${SPARK}${ENV}
</defs>`;

const SCENE = `<g id="scene">${parts.join('\n')}</g>`;
const LIVE = `<use href="#spark" id="spark-live" transform="translate(1470 972)" visibility="hidden"/>
<use href="#env" id="env-live" transform="translate(160 1171)" visibility="hidden"/>
<g id="ring-live" transform="translate(96 172)"><circle r="23" class="ring"/></g>
<use href="#pod" id="pod-live" transform="translate(410 380)"/>`;

/* ---------- stops ---------- */
const STOPS = [
	{ n: 1, name: 'Workshop', title: 'The workshop: build and sign', view: '0 118 520 332', pod: [410, 380],
		p: 'The operator writes BPF C and runs <code>shirudo bpm build</code>. A separate helper, <code>shirudo-build</code>, compiles it with clang 23 for instruction set v4, and libbpf’s gen_loader turns the object into a loader: a small <code>BPF_PROG_TYPE_SYSCALL</code> program whose data carries the payload programs. The helper signs <code>loader_insns ‖ data</code> with the ML-DSA-87 private key as a detached CMS signature.',
		note: 'One signature covers every instruction that ends up attached, because the payload rides inside the signed data. The operator keeps no state about targets, so losing its host loses nothing but the key.' },
	{ n: 2, name: 'Registry', title: 'The registry: publish', view: '640 14 660 304', pod: [780, 200],
		p: '<code>shirudo bpm push</code> publishes versioned packages to an OCI registry, and a signed index names each package by digest. <code>shirudo bpm tree append</code> adds operations to the upatch tree, an append-only, ordered list where each operation adds or deletes one upatch for the targets its selector matches: architecture, kernel release, kernel build ID, kernel config values or node labels.',
		note: 'Each tree generation carries a detached CMS signature and names the one it replaces. The registry is trusted with nothing: the target checks every object’s own signature before acting on it.' },
	{ n: 3, name: 'Pull', title: 'The roof pump: pull, never push', view: '480 250 440 290', pod: [575, 352],
		p: 'Nothing connects into a target. systemd timers start one-shot commands, <code>bpm repo update</code>, <code>bpm upgrade</code> and <code>bpm tree sync</code>, that fetch, verify and load. <code>tree sync</code> verifies the publication against the active config’s signer set, evaluates each new operation’s selector on this target and applies the matching ones in sequence order.',
		note: 'No daemon, no listening socket. A udev rule starts <code>upatch reconcile</code> when a network device appears, to attach XDP upatches. No target command starts another program.' },
	{ n: 4, name: 'Workbench', title: 'The workbench: read once, check', view: '560 546 360 178', pod: [720, 620],
		p: '<code>shirudo upatch load</code> reads the file into memory once, and every later step takes its bytes from that read. It refuses the artifact unless the signed name equals the header name and <code>payload_sha256</code> equals SHA-256 of <code>loader_insns ‖ data</code>, and it holds the register lock from before it touches the pins until the record is appended.',
		note: 'The worker carries runtime authority: a mark a task gets only by executing a file from the dm-verity runtime image upstairs. The guards ask for that mark, not for a user ID or a capability.' },
	{ n: 5, name: 'Gate', title: 'The gate: <code>bpf()</code> meets <code>lsm/bpf</code>', view: '760 540 420 300', pod: [852, 760],
		p: 'Every <code>bpf()</code> call is checked by <code>lsm/bpf</code> at entry. Calls from userspace arrive with <code>kernel</code> false and are filtered: shirudo’s own need runtime authority, and a program load must be a <code>SYSCALL</code> program with a signature. Root cannot load BPF of its own, create maps or attach links, even with <code>CAP_SYS_ADMIN</code>.',
		note: 'Calls made from inside a verified loader reach the hook with <code>kernel</code> true and are allowed. That one argument tells the operator’s code from root’s.' },
	{ n: 6, name: 'Frozen map', title: 'The ice block: <code>__loader.map</code>', view: '560 728 330 262', pod: [722, 902],
		p: 'The kernel can only verify a signature over data it has seen, so the data goes first, into a one-element array map. shirudo sets <code>excl_prog_hash</code> to SHA-256 of the loader’s instructions, so the verifier refuses to bind the map to any other program, then writes the data and freezes the map.',
		note: 'The kernel refuses a signed load whose bound map is not an array, not frozen, has active writers or is not exclusive.' },
	{ n: 7, name: 'Verifier', title: 'The verifier and the vault', view: '340 728 520 266', pod: [784, 902],
		p: '<code>BPF_PROG_LOAD</code> passes the map in <code>fd_array</code>. Inside <code>bpf_check()</code> the kernel binds it and verifies the signature over the loader’s instructions followed by the map’s frozen value against the <code>.bpf</code> keyring. <code>lsm/bpf_prog_load</code> then admits the program only on a good verdict from the right kind of keyring.',
		note: '<code>init</code> enrolled the operator’s certificate in <code>.bpf</code> at boot and sealed the ring. A live signed config can revoke an enrolled key and purge its upatches, but it cannot enroll a new one.' },
	{ n: 8, name: 'Loader & pins', title: 'The loader and the pinboard', view: '940 728 650 266', pod: [1470, 914],
		p: 'A test run starts the loader. Its own <code>bpf()</code> calls create the upatch’s maps and load its programs, and the verifier checks each payload program as usual. shirudo then attaches each program, compares the link the kernel reports with the signed attach metadata, refusing with <code>attach_scope_mismatch</code> when they differ, and pins it under <code>/run/shirudo/bpffs/upatches/&lt;name&gt;/</code>.',
		note: 'The pins keep the links attached after the one-shot command exits. A copy of the artifact goes to <code>/var/lib/shirudo/upatches/</code> so the next boot can restore it.' },
	{ n: 9, name: 'Register', title: 'The ledger in the TPM', view: '380 994 740 240', spark: [476, 1030],
		p: 'The load event is extended into the measurement register under a domain-separated tag and the eventlog takes the record; a failed copy or a refused extension undoes the load. The register is an NV extend index, <code>0x01818E00</code> by default, that behaves like a PCR: each write replaces it with SHA-256 of the old value followed by the event, and it clears at every TPM reset.',
		note: 'Every extend needs a signature from a writer key made inside the TPM at boot, and <code>lsm/tpm_command</code> refuses an <code>NV_Extend</code> of the index to every task without runtime authority. The first write works only while PCRs 9 and 11 hold the values <code>init</code> read, which is why <code>init</code> binds it from the initrd.' },
	{ n: 10, name: 'Evidence', title: 'Home again: evidence, checked offline', view: '0 994 430 246', env: [160, 1171],
		p: 'The operator picks a fresh nonce and runs <code>shirudo attest --nonce=&lt;hex&gt;</code> on the target. The TPM signs a quote over PCRs 0–7, 9 and 11–15 and a certification of the register with its attestation key, and the command adds this boot’s eventlog records. On the operator host, <code>shirudo attest verify</code> checks the nonce, the signatures and the pinned key, the register’s name, that the records replay to the certified value and that PCR 9 carries the anchor, without a TPM.',
		note: 'shirudo writes the evidence document; how it reaches the operator is up to the administrator, since shirudo has no transport of its own. <code>shirudo attest predict</code> computes the expected register from the certificates and artifacts the operator already has.' },
];

const cropSvg = s => {
	let live = '';
	if (s.pod) live = podAt(s.pod[0], s.pod[1]);
	if (s.spark) live = `<use href="#spark" transform="translate(${s.spark[0]} ${s.spark[1]})"/>`;
	if (s.env) live = `<use href="#env" transform="translate(${s.env[0]} ${s.env[1]})"/>`;
	return `<svg viewBox="${s.view}" role="img" aria-label="Close-up of stop ${s.n}: ${esc(s.name)}"><use href="#scene"/>${live}</svg>`;
};
const stopHtml = STOPS.map((s, i) => `
<article class="stop${i % 2 ? ' flip' : ''}" id="stop-${s.n}">
  <figure class="panel">${cropSvg(s)}</figure>
  <div class="stop-text">
    <p class="kicker"><span class="dot">${s.n}</span> Stop ${s.n} · ${esc(s.name)}</p>
    <h3>${s.title}</h3>
    <p>${s.p}</p>
    <aside class="note"><span class="note-head">Field note</span>${s.note}</aside>
  </div>
</article>`).join('');

const chips = STOPS.map(s => `<li><a href="#stop-${s.n}" data-stop="${s.n}"${s.n === 1 ? ' class="now"' : ''}><span class="dot">${s.n}</span>${esc(s.name)}</a></li>`).join('');

const miniPod = c => `<svg viewBox="-40 -24 80 48" class="mini" aria-hidden="true" style="--orange:var(--${c})"><use href="#pod"/></svg>`;
const PASSENGERS = [
	{ c: 'purple', name: 'kernel-cve', kind: 'BPF', text: 'Upatches aimed at single kernel CVEs. Two refuse the path to a bug (<code>AF_ALG</code> sockets and zero-copy splice into them, CVE-2026-31431); three count the inputs that reach one (e1000 TBI frames of length 0, netem packets with an empty linear head, RPL routing headers whose n + 1 exceeds 127).' },
	{ c: 'teal', name: 'kernel-obs', kind: 'BPF', text: 'Host observability: executed programs, network peers and listeners, DNS answers, privilege transitions and access to credential and persistence files. Every hook observes and nothing enforces. Each table lives in one BPF arena that the export drains.' },
	{ c: 'pink', name: 'app-sandbox', kind: 'BPF', text: 'Puts applications in sandboxes that limit what they execute, where they connect and which files they write. It ships sandboxes for Apache httpd and PHP-FPM that keep a web app from rewriting the PHP it serves or starting other programs.' },
	{ c: 'orange-l', name: 'java-base64 · java-sql-inj', kind: 'Java agent', text: 'Signed jars that guard JVM code: one rejects the input shape behind CVE-2026-114938 in <code>Base64$Decoder.decode0</code>, the other blocks structural SQL injection in JDBC statements. A JVM loads the jar, not the kernel, so its signature is checked in userspace and it reaches only JVMs started with shirudo’s <code>JAVA_TOOL_OPTIONS</code>. It is a mitigation inside the application, not a boundary against root.' },
];
const passengerHtml = PASSENGERS.map(p => `
<article class="pass">
  ${miniPod(p.c)}
  <p class="pass-kind">${esc(p.kind)}</p>
  <h3><code>${esc(p.name)}</code></h3>
  <p>${p.text}</p>
</article>`).join('');

/* ---------- extra scene: kernel-obs blind spot ---------- */
const PANELS = (() => {
  const g = [];
  const A = (...s) => g.push(...s);
  const star = (cx, cy, r, c) => {
    let d = '';
    for (let i = 0; i < 5; i++) {
      const ao = -Math.PI / 2 + i * 2 * Math.PI / 5, ai = ao + Math.PI / 5;
      d += (i ? 'L' : 'M') + `${n1(cx + Math.cos(ao) * r)} ${n1(cy + Math.sin(ao) * r)} L${n1(cx + Math.cos(ai) * r * 0.44)} ${n1(cy + Math.sin(ai) * r * 0.44)} `;
    }
    return P(d + 'Z', c, { thin: true });
  };
  const check = (x, y, s = 1) => S(`M${n1(x)} ${n1(y)} l${n1(5 * s)} ${n1(6 * s)} l${n1(11 * s)} ${n1(-14 * s)}`, 'green', 3.6 * s);
  const cross = (x, y, s = 1) => S(`M${n1(x - 7 * s)} ${n1(y - 7 * s)} L${n1(x + 7 * s)} ${n1(y + 7 * s)} M${n1(x + 7 * s)} ${n1(y - 7 * s)} L${n1(x - 7 * s)} ${n1(y + 7 * s)}`, 'red', 4.5 * s);
  const label = (x, y, s, o = {}) => tag(x, y, s, { kind: 'hand', size: o.size ?? 15, c: 'plate', ink: 'ink', pad: 18, ...o });
  const bird = (cx, cy, s = 1, c = 'sun', cd = 'sun-d') => {
    let b = P(`M${n1(cx - 13 * s)} ${n1(cy)} L${n1(cx - 30 * s)} ${n1(cy - 8 * s)} L${n1(cx - 27 * s)} ${n1(cy + 7 * s)} Z`, c, { thin: true });
    b += E(cx, cy, 16 * s, 13 * s, c);
    b += C(cx + 13 * s, cy - 9 * s, 9.5 * s, c);
    b += P(`M${n1(cx + 22 * s)} ${n1(cy - 10 * s)} L${n1(cx + 33 * s)} ${n1(cy - 8 * s)} L${n1(cx + 22 * s)} ${n1(cy - 4 * s)} Z`, 'orange', { thin: true });
    b += C(cx + 15.5 * s, cy - 11 * s, 1.8 * s, 'line', { nostroke: true });
    b += C(cx - 9 * s, cy + 5 * s, 3 * s, 'pink', { nostroke: true, style: 'opacity:.4' });
    b += P(`M${n1(cx - 3 * s)} ${n1(cy - 3 * s)} Q${n1(cx - 15 * s)} ${n1(cy - 12 * s)} ${n1(cx + 5 * s)} ${n1(cy + 3 * s)} Z`, cd, { thin: true });
    b += S(`M${n1(cx + 1 * s)} ${n1(cy + 12 * s)} L${n1(cx + 1 * s)} ${n1(cy + 20 * s)} M${n1(cx + 10 * s)} ${n1(cy + 12 * s)} L${n1(cx + 10 * s)} ${n1(cy + 20 * s)}`, 'orange', 2);
    return '<g>' + b + '</g>';
  };
  const door = (x, y, w, h, num) => {
    let d = R(x, y, w, h, 'steel-l', { w: 2.4, rx: 4 });
    d += S(`M${n1(x + 5)} ${n1(y + 6)} V${n1(y + h - 6)}`, 'steel-d', 1.4);
    d += C(x + w - 7, y + h / 2, 2.2, 'line', { nostroke: true });
    if (num != null) d += T(x + w / 2, y + h + 15, num, { kind: 'mono', size: 11, c: 'ink' });
    return d;
  };
  const metronome = (cx, cy, s = 1) => {
    let m = P(`M${n1(cx - 24 * s)} ${n1(cy + 32 * s)} L${n1(cx - 9 * s)} ${n1(cy - 32 * s)} L${n1(cx + 9 * s)} ${n1(cy - 32 * s)} L${n1(cx + 24 * s)} ${n1(cy + 32 * s)} Z`, 'wood-l', { w: 2.5 });
    m += S(`M${n1(cx)} ${n1(cy + 26 * s)} L${n1(cx - 13 * s)} ${n1(cy - 28 * s)}`, 'line', 3);
    m += C(cx - 13 * s, cy - 28 * s, 3.4 * s, 'red', { thin: true });
    m += C(cx, cy + 26 * s, 3 * s, 'line', { nostroke: true });
    return '<g>' + m + '</g>';
  };
  const parcel = (x, y, w, h) => {
    let p = P(`M${n1(x)} ${n1(y)} L${n1(x + w * 0.42)} ${n1(y - 20)} L${n1(x + w * 0.5)} ${n1(y)} Z`, 'cork-d', { thin: true });
    p += P(`M${n1(x + w)} ${n1(y)} L${n1(x + w * 0.58)} ${n1(y - 20)} L${n1(x + w * 0.5)} ${n1(y)} Z`, 'cork-d', { thin: true });
    p += R(x, y, w, h, 'cork', { w: 3, rx: 5 });
    p += S(`M${n1(x + w / 2)} ${n1(y)} V${n1(y + h)}`, 'wood-l', 6);
    p += S(`M${n1(x)} ${n1(y + h * 0.4)} H${n1(x + w)}`, 'wood-l', 6);
    return p;
  };
  const bigShield = (cx, cy, s = 1) => {
    const w = 32 * s, top = cy - 38 * s;
    let sh = P(`M${n1(cx - w)} ${n1(top)} H${n1(cx + w)} V${n1(cy)} Q${n1(cx + w)} ${n1(cy + 32 * s)} ${n1(cx)} ${n1(cy + 44 * s)} Q${n1(cx - w)} ${n1(cy + 32 * s)} ${n1(cx - w)} ${n1(cy)} Z`, 'blue', { w: 3 });
    sh += S(`M${n1(cx)} ${n1(top + 8)} V${n1(cy + 4 * s)} M${n1(cx - 15 * s)} ${n1(cy - 14 * s)} H${n1(cx + 15 * s)}`, 'blue-l', 5);
    sh += face(cx, cy - 4 * s, 1.05 * s, 'smile');
    return '<g>' + sh + '</g>';
  };

  /* ---- panel kit: one clean single-technique sheet per quiet way.
     Grounded in tatewari's four-channel table (DNS / Ports / Timing / HTTP)
     over the sibling spar implementation; pinned to non-flipping tokens so
     every sheet stays clean white watercolour paper in light and dark. ---- */
  const panel = (draw) => { const gg = []; const AA = (...s) => gg.push(...s); draw(AA); return gg.join(''); };
  const frameBg = (AA, wash) => {
    AA(R(0, 0, 1200, 720, 'plate', { nostroke: true }));
    AA(E(600, 410, 470, 300, wash, { nostroke: true, style: 'opacity:.38' }));
    AA(R(12, 12, 1176, 696, 'none', { w: 4, rx: 22 }));
  };
  const titleBlock = (AA, n, chan, tech) => {
    const t = `Way ${n} · ${chan}`;
    AA(T(601, 63, t, { kind: 'disp', size: 34, c: 'sun-d' }));
    AA(T(600, 61, t, { kind: 'disp', size: 34, c: 'ink' }));
    AA(T(600, 90, tech, { kind: 'mono', size: 15, c: 'rock-d' }));
  };
  const obsNote = (AA, x, y, rec) => {
    AA(R(x, y, 256, 96, 'teal', { w: 3, rx: 10 }));
    Array.from({ length: 6 }, (_, i) => AA(C(x, y + 16 + i * 13, 4, 'plate', { thin: true })));
    AA(R(x + 16, y + 10, 226, 76, 'plate', { thin: true, rx: 4 }));
    AA(T(x + 129, y + 32, 'kernel-obs', { kind: 'mono', size: 14, c: 'ink' }));
    AA(S(`M${x + 30} ${y + 41} H${x + 230}`, 'rule', 2));
    AA(T(x + 30, y + 61, rec, { anchor: 'start', kind: 'mono', size: 12, c: 'rock-d' }));
    AA(T(x + 30, y + 80, 'wrote it down · never read it', { anchor: 'start', kind: 'hand', size: 13, c: 'teal' }));
  };
  const cap = (AA, s) => AA(T(600, 690, s, { kind: 'hand', size: 17, c: 'ink' }));
  const ahead = (AA, x, y, dx, dy, c = 'red') => AA(P(`M${n1(x)} ${n1(y)} l${n1(dx)} ${n1(dy)} l${n1(dy)} ${n1(-dx)} Z`, c, { thin: true }));
  const sticky = (x, y, w, lines, rot) => {
    const lh = 21, h = 16 + lines.length * lh + 14;
    let s = R(0, 0, w, h, 'glass2', { w: 2, rx: 3 });
    s += P(`M${w - 16} ${h} L${w} ${h - 16} L${w} ${h} Z`, 'sun', { thin: true });
    lines.forEach((ln, i) => s += T(14, 28 + i * lh, ln, { anchor: 'start', kind: 'hand', size: 16, c: 'ink' }));
    s += check(w - 26, 14, 1);
    return `<g transform="translate(${x} ${y}) rotate(${rot} ${w / 2} ${h / 2})">${s}</g>`;
  };

  /* ---- Way 1 · DNS — dns_label_exfil ---- */
  const p1 = panel(AA => {
    frameBg(AA, 'ice-l');
    titleBlock(AA, 1, 'DNS', 'dns_label_exfil');
    AA(bird(150, 250, 1.4, 'sun', 'sun-d'));
    AA(label(150, 298, 'SPAR-9f2c', { kind: 'mono', size: 13 }));
    AA(R(64, 330, 172, 40, 'plate', { w: 2.4, rx: 5 }), T(150, 357, '9f 2c 1a', { kind: 'mono', size: 18, c: 'ink' }));
    AA(T(150, 392, 'the secret, in hex', { kind: 'hand', size: 15, c: 'rock-d' }));
    AA(R(392, 150, 486, 120, 'plate', { w: 2.6, rx: 10 }));
    AA(R(410, 182, 118, 54, 'ice-l', { w: 2.2, rx: 6 }), T(469, 217, '9f2c1a', { kind: 'mono', size: 18, c: 'ink' }));
    AA(T(540, 222, '.', { kind: 'disp', size: 24, c: 'ink' }));
    AA(R(556, 182, 134, 54, 'glass2', { w: 2.2, rx: 6 }), T(623, 216, 'telemetry', { kind: 'mono', size: 15, c: 'ink' }));
    AA(T(700, 222, '.', { kind: 'disp', size: 24, c: 'ink' }));
    AA(R(716, 182, 110, 54, 'pink-l', { w: 2.2, rx: 6 }), T(771, 216, 'example', { kind: 'mono', size: 15, c: 'ink' }));
    AA(T(635, 300, 'encoded bytes ride in the question name', { kind: 'hand', size: 16, c: 'rock-d' }));
    AA(S('M238 344 Q360 320 452 242', 'red', 3, { style: 'stroke-dasharray:4 7' }));
    ahead(AA, 452, 242, -6, 10, 'red');
    AA(bird(344, 150, 1.0, 'fur', 'rock'));
    AA(S('M452 168 Q710 140 968 236', 'rock', 2.4, { style: 'stroke-dasharray:3 9' }));
    AA(R(968, 232, 128, 86, 'red', { w: 3, rx: 16 }));
    AA(P('M968 232 Q968 210 1032 210 Q1096 210 1096 232 Z', 'red', { w: 3 }));
    AA(R(986, 266, 92, 8, 'line', { rx: 2, nostroke: true }));
    AA(R(1092, 214, 6, 30, 'sun', { rx: 1, thin: true }));
    AA(label(1032, 344, 'resolver · UDP 53', { kind: 'mono', size: 13 }));
    obsNote(AA, 60, 470, 'the name — never the payload');
    AA(sticky(930, 452, 212, ['Up to four names', 'per address'], 3));
    AA(sticky(936, 560, 220, ['Only DNS on', 'UDP port 53 is parsed'], -3));
    cap(AA, 'The question name itself is the payload; the observer stores the name, not that it was smuggled.');
  });

  /* ---- Way 2 · Ports — metadata_covert_channel ---- */
  const p2 = panel(AA => {
    frameBg(AA, 'glass2');
    titleBlock(AA, 2, 'Ports', 'metadata_covert_channel');
    AA(T(600, 138, 'sixteen destination ports · 41100 – 41115', { kind: 'mono', size: 15, c: 'rock-d' }));
    const startx = 97, dw = 46, gap = 18;
    for (let i = 0; i < 16; i++) AA(door(startx + i * (dw + gap), 186, dw, 72, String(41100 + i)));
    AA(bird(150, 430, 1.3, 'sun', 'sun-d'));
    AA(label(150, 476, 'SPAR-9f2c', { kind: 'mono', size: 13 }));
    const centre = i => startx + i * (dw + gap) + dw / 2;
    [3, 9, 13].forEach(i => AA(S(`M184 420 Q${n1(centre(i) - 40)} 360 ${n1(centre(i))} 262`, 'orange', 2.4, { style: 'stroke-dasharray:3 9;opacity:.85' })));
    AA(R(446, 300, 320, 42, 'plate', { w: 2.4, rx: 6 }), T(606, 327, 'port 41109  →  nibble 1001', { kind: 'mono', size: 15, c: 'ink' }));
    obsNote(AA, 60, 540, 'peer:port totals / interval');
    AA(sticky(520, 520, 268, ['Which of 16 ports', 'carries each nibble'], -2));
    AA(sticky(820, 520, 250, ['Per-interval totals,', 'not per request'], 3));
    cap(AA, 'Only the choice of port carries the bits; every visit looks ordinary in the ledger.');
  });

  /* ---- Way 3 · Timing — metadata_covert_channel ---- */
  const p3 = panel(AA => {
    frameBg(AA, 'pink-l');
    titleBlock(AA, 3, 'Timing', 'metadata_covert_channel');
    AA(door(110, 170, 70, 150, null));
    AA(bird(236, 250, 1.2, 'sun', 'sun-d'));
    AA(label(236, 296, 'SPAR-9f2c', { kind: 'mono', size: 13 }));
    AA(S('M190 230 l16 -5 M192 246 l18 0 M190 262 l16 6', 'line', 2.6));
    const ty = 250, pts = [380, 425, 560, 785, 1100], gaps = ['150 ms', '450 ms', '750 ms', '1050 ms'];
    AA(S(`M360 ${ty} H1120`, 'line', 3));
    pts.forEach(px => { AA(S(`M${px} ${ty - 16} V${ty + 16}`, 'red', 3)); AA(T(px, ty - 24, 'knock', { kind: 'hand', size: 12, c: 'rock-d' })); });
    for (let i = 0; i < 4; i++) {
      const mid = (pts[i] + pts[i + 1]) / 2;
      AA(S(`M${pts[i] + 6} ${ty + 34} H${pts[i + 1] - 6}`, 'rock-d', 1.8));
      AA(T(mid, ty + 54, gaps[i], { kind: 'mono', size: 12, c: 'ink' }));
    }
    AA(R(360, 360, 330, 40, 'plate', { w: 2.4, rx: 6 }), T(525, 386, 'short gap → 0 · long gap → 1', { kind: 'mono', size: 14, c: 'ink' }));
    AA(metronome(1075, 405, 1.0));
    obsNote(AA, 60, 470, 'first-seen · last-seen only');
    AA(sticky(430, 470, 264, ['The gaps between knocks', 'carry the message'], 3));
    AA(sticky(740, 470, 252, ['First/last seen only —', 'pacing is not modelled'], -3));
    cap(AA, 'The message rides in the silences between knocks; the ledger keeps totals, not the spacing.');
  });

  /* ---- Way 4 · HTTP — payload_encoding_mimicry (the one a content shield catches) ---- */
  const p4 = panel(AA => {
    frameBg(AA, 'ice-l');
    titleBlock(AA, 4, 'HTTP', 'payload_encoding_mimicry');
    AA(parcel(430, 168, 190, 118));
    AA(bird(525, 158, 0.9, 'sun', 'sun-d'));
    AA(`<g transform="rotate(-8 525 214)">${R(470, 200, 112, 26, 'none', { w: 2.2, style: 'stroke:var(--red)' })}${T(526, 218, 'looks like metrics', { kind: 'mono', size: 12, c: 'red' })}</g>`);
    AA(R(405, 300, 240, 32, 'plate', { w: 2.2, rx: 5 }), T(525, 322, '?d=U1BBUi05ZjJj&ok=1', { kind: 'mono', size: 13, c: 'ink' }));
    obsNote(AA, 812, 150, 'bytes and peer, not content');
    AA(T(812, 300, 'the observer never opens it', { anchor: 'start', kind: 'hand', size: 14, c: 'rock-d' }));
    AA(S('M40 372 H1160', 'wood', 6, { style: 'stroke-dasharray:2 10' }));
    AA(T(52, 364, 'metadata stops here', { anchor: 'start', kind: 'hand', size: 14, c: 'rock-d' }));
    AA(C(300, 500, 46, 'blue', { w: 3 }), face(300, 494, 1.5, 'smile'));
    AA(label(300, 562, 'Java agent · reads content', { kind: 'mono', size: 12 }));
    AA(C(372, 500, 20, 'glass', { w: 3 }), C(372, 500, 20, 'none', { w: 2, style: 'stroke:var(--blue-d)' }), S('M386 514 l16 16', 'blue-d', 6));
    AA(parcel(430, 470, 150, 92));
    AA(R(636, 470, 338, 40, 'plate', { w: 2.4, rx: 6 }), T(805, 496, 'U1BBUi05ZjJj  =  SPAR-9f2c', { kind: 'mono', size: 15, c: 'ink' }));
    AA(R(690, 528, 150, 34, 'plate', { w: 2, rx: 4 }), T(765, 550, 'SPAR-9f2c', { kind: 'mono', size: 13, c: 'ink' }));
    AA(cross(872, 545, 1.2));
    AA(T(940, 552, 'caught', { kind: 'hand', size: 18, c: 'red' }));
    AA(sticky(60, 150, 216, ['Blind spot: payloads', 'are not recorded'], -3));
    AA(sticky(986, 440, 200, ['Caught: the content', 'shield decodes it'], 3));
    cap(AA, 'Metadata never sees inside; the shield that reads content opens the parcel and catches it.');
  });

  return { p1, p2, p3, p4 };
})();

/* ---------- page ---------- */
const HTML = `<title>Shirudo Field Trip</title>
<meta name="claude:viewport-fit-sides" content="cover">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Luckiest+Guy&family=Patrick+Hand&family=Nunito:wght@400;600;800&family=JetBrains+Mono:wght@500;700&display=swap">
<style>
/* Layout: a picture-book spread. One cutaway map of the whole trip, then one
   comic panel per stop with a notebook-paper field note beside it. */
:root {
  --page: #f4f6ff; --text: #231a3e; --text-soft: #5b5379; --card: #ffffff;
  --ink: #231a3e; --line: #2a2046; --edge: #2a2046; --plate: #ffffff;
  --sky: #86cfff; --sky2: #e2f4ff; --cloud: #ffffff;
  --sun: #ffc93c; --sun-d: #f5a524; --orange: #ff8a3d; --orange-l: #ffb070;
  --pink: #ff5c8a; --pink-l: #ffd0dd; --red: #ee4646; --teal: #18b5a5; --green: #2ebf6b;
  --purple: #7b5cf0; --purple-l: #c9bcff; --blue: #3b82f6; --blue-d: #2457c5; --blue-l: #cfe2ff;
  --grass: #6ccb7a; --grass-d: #3fa35a; --soil: #c99d73; --soil-d: #a67b52; --rock: #8a8fa8; --rock-d: #6d728c;
  --op-wall: #cfe6ff; --op-room: #f3f9ff; --roof: #ff6f91; --roof-d: #d94b72;
  --house: #ffd7a1; --room: #fff4e3; --room2: #f2f7ff; --wood: #c98b55; --wood-l: #e8b884; --shaft: #e9dcc6;
  --steel: #a9b4d0; --steel-d: #7f8bad; --steel-l: #ccd4e8; --glass: #cdeffe; --glass2: #ffe9a8;
  --ice: #bfefff; --ice-l: #e4f8ff; --ice-d: #8fd8f2; --screen: #1e2c48; --scr: #7cf2a5;
  --kernel: #e9e3ff; --chip: #1f5a64; --chip-l: #2f7c88; --chip-d: #143e45; --cork: #e0b47e; --cork-d: #b98a54;
  --fur: #9aa0b5; --fur-l: #d8dbe6; --mask: #3b3550; --route: #ff8a3d;
  --rule: #b9d3f2; --margin: #f59bae; --note: #fffdf3;
  --f-disp: "Luckiest Guy", "Arial Black", Impact, sans-serif;
  --f-hand: "Patrick Hand", "Comic Sans MS", "Chalkboard SE", cursive;
  --f-body: "Nunito", "Segoe UI", system-ui, sans-serif;
  --f-mono: "JetBrains Mono", ui-monospace, "SFMono-Regular", Menlo, monospace;
}
@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) {
  --page: #15122a; --text: #f1eeff; --text-soft: #b8b0d8; --card: #221d3d;
  --sky: #1f2b63; --sky2: #3b4f94; --cloud: #dfe6ff; --kernel: #d8cffb;
  --grass: #4fae63; --grass-d: #2f7d46; --soil: #8a6649; --soil-d: #6d4f37; --rock: #5d627c; --rock-d: #474b62;
  --house: #f0c387; --room: #f7e9d2; --op-wall: #b9d4f3; --op-room: #e8f1fd;
  --rule: #3e4f80; --margin: #a04a62; --note: #1f1b38; --edge: #7a6fc4; color-scheme: dark;
} }
:root[data-theme="dark"] {
  --page: #15122a; --text: #f1eeff; --text-soft: #b8b0d8; --card: #221d3d;
  --sky: #1f2b63; --sky2: #3b4f94; --cloud: #dfe6ff; --kernel: #d8cffb;
  --grass: #4fae63; --grass-d: #2f7d46; --soil: #8a6649; --soil-d: #6d4f37; --rock: #5d627c; --rock-d: #474b62;
  --house: #f0c387; --room: #f7e9d2; --op-wall: #b9d4f3; --op-room: #e8f1fd;
  --rule: #3e4f80; --margin: #a04a62; --note: #1f1b38; --edge: #7a6fc4; color-scheme: dark;
}
* { box-sizing: border-box; }
body { background: var(--page); color: var(--text); font-family: var(--f-body); font-size: 16px; line-height: 1.6; }
.wrap { max-width: 1240px; margin: 0 auto; padding-left: max(16px, env(safe-area-inset-left, 0px)); padding-right: max(16px, env(safe-area-inset-right, 0px)); }
code { font-family: var(--f-mono); font-size: .86em; font-weight: 500; background: color-mix(in srgb, var(--purple) 12%, transparent); padding: .05em .32em; border-radius: 5px; overflow-wrap: anywhere; }
header.cover { padding-block: 40px 18px; }
.eyebrow { font-family: var(--f-hand); font-size: 20px; color: var(--text-soft); margin: 0 0 6px; }
h1 { font-family: var(--f-disp); font-weight: 400; font-size: clamp(40px, 7.4vw, 86px); line-height: .98; margin: 0 0 16px; letter-spacing: .01em; text-wrap: balance; }
h1 .w { display: inline-block; -webkit-text-stroke: 2px var(--edge); paint-order: stroke fill; text-shadow: 4px 4px 0 var(--edge); }
h1 .w1 { color: var(--sun); transform: rotate(-2deg); } h1 .w2 { color: var(--pink); transform: rotate(1.5deg); } h1 .w3 { color: var(--teal); transform: rotate(-1deg); }
.lede { font-size: clamp(17px, 2.1vw, 20px); max-width: 62ch; margin: 0; text-wrap: pretty; }
.map { padding-block: 18px 8px; }
.map-frame { border: 4px solid var(--edge); border-radius: 22px; box-shadow: 7px 7px 0 var(--edge); background: var(--sky2); overflow: hidden; }
.map-scroll { overflow-x: auto; -webkit-overflow-scrolling: touch; }
.map-scroll svg { display: block; width: 100%; min-width: 1000px; height: auto; }
.swipe { display: none; font-family: var(--f-hand); font-size: 17px; color: var(--text-soft); margin: 10px 0 0; }
.ways-stack { display: grid; grid-template-columns: minmax(0, 1fr); gap: 26px; }
.ways-stack figure { margin: 0; min-width: 0; }
.ways-stack figcaption { font-family: var(--f-hand); font-size: 19px; color: var(--text-soft); margin: 0 0 8px; display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; }
.ways-stack figcaption code { font-size: .78em; }
.ring { fill: none; stroke: var(--pink); stroke-width: 5; transform-box: fill-box; transform-origin: center; animation: ring 1.4s ease-in-out infinite; }
@keyframes ring { 0%, 100% { transform: scale(1); opacity: 1; } 50% { transform: scale(1.28); opacity: .45; } }
.tour { display: flex; flex-wrap: wrap; gap: 12px 16px; align-items: center; margin-top: 18px; }
.legend { list-style: none; margin: 0; padding: 0; display: flex; flex-wrap: wrap; gap: 8px; flex: 1 1 520px; min-width: 0; }
.legend a { display: inline-flex; align-items: center; gap: 7px; padding: 5px 12px 5px 6px; border: 2.5px solid var(--edge); border-radius: 999px; background: var(--card); color: var(--text); text-decoration: none; font-weight: 700; font-size: 14px; transition: transform .15s, background .15s; }
.legend a:hover, .legend a:focus-visible { transform: translateY(-2px); }
.legend a.now { background: var(--sun); color: #231a3e; }
.dot { display: inline-grid; place-items: center; min-width: 26px; height: 26px; padding: 0 5px; border-radius: 999px; background: var(--sun); color: #231a3e; border: 2.5px solid var(--edge); font-family: var(--f-disp); font-size: 15px; line-height: 1; padding-top: 3px; }
.legend a.now .dot { background: var(--plate); }
button.play { font: 800 15px var(--f-body); color: #231a3e; background: var(--teal); border: 3px solid var(--edge); border-radius: 14px; padding: 8px 16px; box-shadow: 3px 3px 0 var(--edge); cursor: pointer; }
button.play:active { transform: translate(2px, 2px); box-shadow: 1px 1px 0 var(--edge); }
a:focus-visible, button:focus-visible { outline: 3px solid var(--pink); outline-offset: 3px; }
h2 { font-family: var(--f-disp); font-weight: 400; font-size: clamp(30px, 4.6vw, 46px); line-height: 1.05; margin: 0 0 8px; letter-spacing: .01em; text-wrap: balance; }
h2 + .sub { margin: 0 0 26px; color: var(--text-soft); max-width: 64ch; }
section.stops, section.passengers, section.boot { padding-block: 48px 8px; }
.stop { display: grid; grid-template-columns: minmax(0, 1.25fr) minmax(0, 1fr); gap: 28px; align-items: center; margin-bottom: 44px; }
.stop.flip .panel { order: 2; }
.panel { margin: 0; border: 4px solid var(--edge); border-radius: 18px; box-shadow: 6px 6px 0 var(--edge); overflow: hidden; background: var(--sky2); min-width: 0; }
.panel svg { display: block; width: 100%; height: auto; }
.stop-text { min-width: 0; }
.kicker { font-family: var(--f-hand); font-size: 19px; color: var(--text-soft); margin: 0 0 4px; display: flex; align-items: center; gap: 8px; }
.stop h3 { font-family: var(--f-disp); font-weight: 400; font-size: clamp(24px, 3vw, 31px); line-height: 1.1; margin: 0 0 10px; letter-spacing: .01em; text-wrap: balance; }
.stop h3 code { font-size: .78em; background: none; padding: 0; }
.stop p { margin: 0 0 14px; max-width: 62ch; }
.note { font-family: var(--f-hand); font-size: 18.5px; line-height: 28px; color: var(--text); background-color: var(--note);
  background-image: linear-gradient(90deg, transparent 34px, var(--margin) 34px, var(--margin) 36px, transparent 36px), repeating-linear-gradient(to bottom, transparent 0 27px, var(--rule) 27px 28px);
  padding: 14px 16px 14px 48px; border: 2.5px solid var(--edge); border-radius: 6px; transform: rotate(-.6deg); box-shadow: 4px 4px 0 color-mix(in srgb, var(--edge) 85%, transparent); }
.stop.flip .note { transform: rotate(.6deg); }
.note code { font-size: .8em; }
.note-head { display: block; font-family: var(--f-disp); font-size: 15px; letter-spacing: .06em; color: var(--pink); line-height: 28px; }
.pass-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 18px; }
.pass { background: var(--card); border: 3px solid var(--edge); border-radius: 18px; padding: 18px; box-shadow: 5px 5px 0 var(--edge); min-width: 0; }
.pass .mini { width: 74px; height: auto; display: block; margin-bottom: 8px; }
.pass-kind { font-family: var(--f-hand); font-size: 18px; color: var(--text-soft); margin: 0; }
.pass h3 { margin: 0 0 8px; font-size: 17px; } .pass h3 code { background: none; padding: 0; font-size: 1em; font-weight: 700; }
.pass p:last-child { margin: 0; font-size: 15px; }
section.cve, section.ways { padding-block: 48px 8px; }
.cve-flaw { background: var(--card); border: 3px solid var(--edge); border-radius: 18px; padding: 18px 20px; box-shadow: 5px 5px 0 var(--edge); margin-bottom: 18px; min-width: 0; }
.cve-flaw.bypass { margin-top: 18px; margin-bottom: 0; }
.cve-two { display: grid; grid-template-columns: repeat(auto-fit, minmax(290px, 1fr)); gap: 18px; }
.cve-card { background: var(--card); border: 3px solid var(--edge); border-radius: 18px; padding: 18px 20px; box-shadow: 5px 5px 0 var(--edge); min-width: 0; }
.cve-card.blunt { border-top: 7px solid var(--sun); }
.cve-card.precise { border-top: 7px solid var(--teal); }
.cve-kind { font-family: var(--f-hand); font-size: 18px; color: var(--text-soft); margin: 0; }
.cve h3 { font-family: var(--f-disp); font-weight: 400; font-size: clamp(21px, 2.6vw, 26px); line-height: 1.1; margin: 2px 0 10px; letter-spacing: .01em; text-wrap: balance; }
.cve-card p, .cve-flaw p { margin: 0 0 12px; max-width: 64ch; }
.cve-card p:last-child, .cve-flaw p:last-child { margin-bottom: 0; }
.cve-flaw.bypass p { max-width: 74ch; }
.hookline { font-family: var(--f-mono); font-size: 14px; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.verdict { font-family: var(--f-mono); font-size: 12px; font-weight: 700; padding: 2px 8px; border-radius: 999px; border: 2px solid var(--edge); background: var(--pink); color: #231a3e; }
.cve pre { margin: 0 0 12px; background: var(--sky2); border: 2.5px solid var(--edge); border-radius: 10px; padding: 12px 14px; overflow-x: auto; }
.cve pre code { font-family: var(--f-mono); font-size: 13px; line-height: 1.5; background: none; padding: 0; white-space: pre; }
.cve .note { margin-top: 14px; max-width: none; }
.boot-strip { display: grid; grid-template-columns: minmax(0, 1fr) 150px minmax(0, 1fr); gap: 18px; align-items: stretch; }
.boot-card { background: var(--card); border: 3px solid var(--edge); border-radius: 18px; padding: 18px 20px; box-shadow: 5px 5px 0 var(--edge); min-width: 0; }
.boot-card h3 { font-family: var(--f-disp); font-weight: 400; font-size: 23px; margin: 0 0 2px; letter-spacing: .02em; }
.boot-card .unit { font-family: var(--f-mono); font-size: 13px; color: var(--text-soft); margin: 0 0 10px; }
.boot-card ol { margin: 0; padding-left: 22px; } .boot-card li { margin-bottom: 6px; } .boot-card li::marker { font-family: var(--f-disp); color: var(--pink); }
.switch { display: grid; place-items: center; text-align: center; font-family: var(--f-hand); font-size: 18px; line-height: 1.3; color: var(--text); }
.switch svg { width: 110px; height: auto; display: block; margin: 0 auto 6px; }
footer { padding-block: 40px 56px; color: var(--text-soft); font-size: 14.5px; }
footer p { max-width: 80ch; margin: 0 0 8px; }
@media (max-width: 820px) {
  .stop { grid-template-columns: minmax(0, 1fr); gap: 16px; }
  .stop.flip .panel { order: 0; }
  .boot-strip { grid-template-columns: minmax(0, 1fr); }
  .switch svg { transform: rotate(90deg); width: 70px; }
  .swipe { display: block; }
}
@media (prefers-reduced-motion: reduce) { .ring { animation: none; } .legend a { transition: none; } }
</style>

<header class="cover wrap">
  <p class="eyebrow">A picture-book tour of a BPF security platform</p>
  <h1><span class="w w1">The</span> <span class="w w2">signed-BPF</span> <span class="w w3">field trip</span></h1>
  <p class="lede">Ride along with one signed <code>.upatch</code> as it leaves the operator’s workshop, waits in the registry, gets pulled down into a target, passes the kernel’s gate and lands in the TPM’s ledger. Then follow the proof back home.</p>
</header>

<section class="map wrap" aria-label="Map of the whole trip">
  <div class="map-frame"><div class="map-scroll">
    <svg id="map" class="scene" viewBox="0 0 1600 1240" role="img" aria-label="Cutaway of shirudo: the operator's workshop on a hill, the OCI registry on a cloud, the target host above ground, the kernel underground and the TPM in the bedrock, joined by the route of one signed upatch.">
      ${DEFS}
      ${SCENE}
      ${LIVE}
    </svg>
  </div></div>
  <p class="swipe">Swipe sideways to explore the whole map.</p>
  <div class="tour">
    <ol class="legend" aria-label="Stops">${chips}</ol>
    <button type="button" class="play" id="tour-toggle" aria-pressed="true">Pause tour</button>
  </div>
</section>

<section class="stops wrap" aria-label="The stops">
  <h2>Ten stops, one signature</h2>
  <p class="sub">Each panel is a close-up of the map above. The pictures are metaphors; the names, paths, hooks and numbers in them are the real ones from shirudo’s documentation.</p>
  ${stopHtml}
</section>

<section class="passengers wrap" aria-label="Kinds of upatch">
  <h2>Other passengers</h2>
  <p class="sub">The packages under <code>upatches/</code> in this tree. Most are BPF and take the signed-loader path above; the Java agents take a weaker one.</p>
  <div class="pass-grid">${passengerHtml}</div>
</section>

<section class="cve wrap" aria-label="Worked example: CVE-2026-31431">
  <h2>One CVE, worked end to end</h2>
  <p class="sub">The <code>kernel-cve</code> packages above name <code>CVE-2026-31431</code> twice. Here is why one flaw ships with two different shields, and what a shield has to deny to actually close it rather than just look closed.</p>

  <article class="cve-flaw">
    <p class="cve-kind">The flaw · <code>crypto/algif_aead</code></p>
    <h3>A cleanup that scrubs the wrong pages</h3>
    <p>When an AEAD operation over an <code>AF_ALG</code> socket hits its copy-failure path, the kernel writes back into the source scatter-gather pages it was reading from. That is harmless when the socket owns those pages: an ordinary <code>sendmsg</code> copies the caller’s bytes in, so the pages are the socket’s own. It corrupts memory the socket does not own only when a <em>zero-copy splice</em> (<code>MSG_SPLICE_PAGES</code>) has aliased foreign pages into the socket’s send list first. So the bug has exactly one precondition — foreign pages on the send list — and only the splice path puts them there.</p>
  </article>

  <div class="cve-two">
    <article class="cve-card blunt">
      <p class="cve-kind">Shield A · blunt</p>
      <h3>Refuse the whole subsystem</h3>
      <p class="hookline"><code>lsm/socket_create</code> <span class="verdict">-EPERM</span></p>
      <pre><code>SEC("lsm/socket_create")
if (family == AF_ALG)   /* 38 */
    return -EPERM;</code></pre>
      <p>No <code>AF_ALG</code> socket opens at all, so the vulnerable code is simply never reached. The cost is that it also removes every other use of the kernel’s crypto through sockets — aead, skcipher, hash, rng — so this is the shield for a host that has no need of socket crypto.</p>
    </article>

    <article class="cve-card precise">
      <p class="cve-kind">Shield B · precise</p>
      <h3>Refuse only the one dangerous send</h3>
      <p class="hookline"><code>lsm/socket_sendmsg</code> <span class="verdict">-EACCES</span></p>
      <pre><code>SEC("lsm/socket_sendmsg")
if (BPF_CORE_READ(sock, sk,
      __sk_common.skc_family) != AF_ALG)
    return 0;
if (msg-&gt;msg_flags &amp; MSG_SPLICE_PAGES)
    return -EACCES;</code></pre>
      <p>The socket still opens and every <em>copying</em> use keeps working; only a <code>MSG_SPLICE_PAGES</code> send into an <code>AF_ALG</code> socket — the single way to alias foreign pages in — is refused. It reads the family and the flag from the generic <code>struct sock</code> and <code>struct msghdr</code>, which carry BTF, so it is CO-RE and rides from one kernel to the next.</p>
    </article>
  </div>

  <article class="cve-flaw bypass">
    <p class="cve-kind">Why one hook isn’t enough</p>
    <h3>Deny the precondition, not a symptom</h3>
    <p>Picture a shield that tried to catch the bug where it fails — say, keyed on “an AEAD decrypt that returns an error.” It would be easy to never meet on those terms. The same copy-failure writeback is reachable through <code>skcipher</code>, <code>hash</code> and <code>rng</code> as well as aead, and on the encrypt side as well as decrypt. Worse for the defender, the operation and the algorithm live in the crypto module’s private <code>af_alg_ctx</code>, which carries no BTF, so a CO-RE shield cannot even read them without hard-coded offsets that shatter on the next kernel build. A shield pinned to one symptom is a shield you walk around by changing algorithm or direction.</p>
    <p>That is why the shield that holds does not chase the symptom at all: it denies the one precondition every variant shares — foreign pages aliased in by a zero-copy splice — which lives in the generic structs a shield <em>can</em> read, and which no choice of algorithm or operation changes. Shield A denies it by removing the socket; Shield B denies it by removing the splice. The honest costs sit right next to the shields: A breaks legitimate crypto, and B trusts that <code>MSG_SPLICE_PAGES</code> into an <code>AF_ALG</code> socket is the <em>only</em> route to foreign pages on the send list. The operator chooses per host instead of pretending one answer fits every machine.</p>
    <aside class="note"><span class="note-head">Watching, not enforcing</span>A third program in the same package only observes: it marks a socket when a splice aliases foreign pages into it, then counts the marked sockets whose aead op later fails — the exact foreign-page writeback — against every aead op as the denominator. It blocks nothing; it tells the operator whether the path is actually being taken on this host.</aside>
  </article>
</section>

<section class="ways wrap" aria-label="Four quiet ways out: what a metadata-only observer records but does not interpret">
  <h2>Four quiet ways out</h2>
  <p class="sub"><code>kernel-obs</code> writes down who talked to whom — peer, port, bytes, per interval, and the names DNS resolved — and never records a payload. A metadata-only observer can record all four of these channels and flag none: the blind spot is not what it can’t see, it’s what it doesn’t interpret. It’s not magic; it’s encoding. (A localhost demonstration against a model of the documented telemetry, not an attack on a live deployment.)</p>
  <div class="ways-stack">
    <figure>
      <figcaption>Way 1 · DNS — <code>dns_label_exfil</code></figcaption>
      <div class="map-frame"><div class="map-scroll">
        <svg viewBox="0 0 1200 720" role="img" aria-label="DNS channel: a canary encodes a secret in hex into the question name 9f2c1a.telemetry.example; a pigeon carries it to a resolver on UDP port 53. The kernel-obs notebook records the name but never the payload, up to four names per address.">${PANELS.p1}</svg>
      </div></div>
    </figure>
    <figure>
      <figcaption>Way 2 · Ports — <code>metadata_covert_channel</code></figcaption>
      <div class="map-frame"><div class="map-scroll">
        <svg viewBox="0 0 1200 720" role="img" aria-label="Ports channel: a canary chooses among sixteen destination ports 41100 to 41115, and which port is used carries each nibble. The observer records peer and port totals per interval, never why that port.">${PANELS.p2}</svg>
      </div></div>
    </figure>
    <figure>
      <figcaption>Way 3 · Timing — <code>metadata_covert_channel</code></figcaption>
      <div class="map-frame"><div class="map-scroll">
        <svg viewBox="0 0 1200 720" role="img" aria-label="Timing channel: a canary knocks at uneven gaps of 150, 450, 750 and 1050 milliseconds, and the gaps carry the message. The observer records only first-seen and last-seen times; nothing models pacing.">${PANELS.p3}</svg>
      </div></div>
    </figure>
    <figure>
      <figcaption>Way 4 · HTTP — <code>payload_encoding_mimicry</code></figcaption>
      <div class="map-frame"><div class="map-scroll">
        <svg viewBox="0 0 1200 720" role="img" aria-label="HTTP channel: a base64 query parameter that looks like metrics carries the payload. The metadata observer records bytes and peer but not content, so a content-reading Java shield opens it, decodes U1BBUi05ZjJj to SPAR-9f2c and catches it with a red cross.">${PANELS.p4}</svg>
      </div></div>
    </figure>
  </div>
  <p class="swipe">Swipe sideways to see a whole panel.</p>
</section>

<section class="boot wrap" aria-label="Boot">
  <h2>Every morning: init runs twice</h2>
  <p class="sub">BPF programs do not survive a reboot, so each boot starts the register from zero and loads the archived upatches again.</p>
  <div class="boot-strip">
    <div class="boot-card">
      <h3>In the initrd</h3>
      <p class="unit">shirudo-initrd.service</p>
      <ol>
        <li>Read the bootstrap settings the UKI authenticates and run the pre-flight: BPF LSM, signed-loader ABI, <code>.bpf</code> keyring, TPM.</li>
        <li>Bind <code>/var/lib/shirudo</code> and mount the private tmpfs and bpffs under <code>/run/shirudo</code>.</li>
        <li>Map the runtime image with dm-verity, check its root hash, then select and verify the config image.</li>
        <li>Enroll and seal the <code>.dm-verity</code> and <code>.bpf</code> keyrings and label the state.</li>
        <li>Attach the guards, restore the archived upatches and bind the register while PCRs 9 and 11 hold the policy values.</li>
      </ol>
    </div>
    <div class="switch">
      <svg viewBox="0 0 120 60" aria-hidden="true"><path d="M6 30 H96" style="fill:none;stroke:var(--line);stroke-width:7;stroke-linecap:round"/><path d="M84 12 L112 30 L84 48 Z" style="fill:var(--sun);stroke:var(--line);stroke-width:4;stroke-linejoin:round"/></svg>
      <span><code>leave-initrd</code> moves PCR 11; mounts and pins under <code>/run</code> cross over</span>
    </div>
    <div class="boot-card">
      <h3>In the root file system</h3>
      <p class="unit">shirudo.service</p>
      <ol>
        <li>Start the binary from the verified runtime image.</li>
        <li>Check what the initrd run left behind.</li>
        <li>Adopt its pending record from <code>/run/shirudo/eventlog.pending</code>. A re-run of <code>init</code> adds no register event.</li>
      </ol>
    </div>
  </div>
</section>

<footer class="wrap">
  <p>Drawn from <code>Documentation/internals/architecture.rst</code>, <code>signed-loader.rst</code> and <code>boot-flow.rst</code>, <code>Documentation/concepts/measurement-register.rst</code> and <code>upatches-and-packages.rst</code>, and the READMEs under <code>upatches/</code>. Where the code and the docs disagree, the code is right.</p>
  <p>Not shown: the eight carried kernel patches, live config activation, the tamper counters and the threat model’s residual risks.</p>
</footer>

<script>
(() => {
  const $ = id => document.getElementById(id);
  const route = $('route-path'), wire = $('wire-path'), tubeP = $('evidence-path');
  const pod = $('pod-live'), spark = $('spark-live'), env = $('env-live'), ring = $('ring-live');
  const btn = $('tour-toggle');
  const chips = Array.from(document.querySelectorAll('.legend [data-stop]'));
  if (!route || !route.getTotalLength) return;
  const MARKS = ${JSON.stringify(MARKS)};
  const POD_STOPS = [[1,410,380],[2,780,200],[3,575,352],[4,720,620],[5,852,760],[6,722,902],[7,784,902],[8,1051,852],[8,1470,914]];
  const nearest = (path, x, y) => {
    const L = path.getTotalLength(); let best = 0, bd = Infinity;
    for (let s = 0; s <= L; s += 2) { const p = path.getPointAtLength(s); const d = (p.x - x) ** 2 + (p.y - y) ** 2; if (d < bd) { bd = d; best = s; } }
    return best;
  };
  const place = (el, p) => el.setAttribute('transform', 'translate(' + p.x.toFixed(1) + ' ' + p.y.toFixed(1) + ')');
  const setStop = n => {
    const m = MARKS[n]; if (m) ring.setAttribute('transform', 'translate(' + m[0] + ' ' + m[1] + ')');
    chips.forEach(c => c.classList.toggle('now', c.dataset.stop === String(n)));
  };
  const seq = []; let prev = null;
  POD_STOPS.forEach(([n, x, y], i) => {
    const s = nearest(route, x, y);
    if (prev !== null) seq.push({ type: 'move', el: pod, path: route, a: prev, b: s, speed: 300 });
    seq.push({ type: 'dwell', stop: n, t: i === POD_STOPS.length - 1 ? 1.0 : 1.9 });
    prev = s;
  });
  seq.push({ type: 'show', el: spark }, { type: 'move', el: spark, path: wire, a: 0, b: wire.getTotalLength(), speed: 520, stop: 9 },
    { type: 'dwell', stop: 9, t: 2.0 }, { type: 'hide', el: spark },
    { type: 'show', el: env }, { type: 'move', el: env, path: tubeP, a: 0, b: tubeP.getTotalLength(), speed: 620, stop: 10 },
    { type: 'dwell', stop: 10, t: 2.4 }, { type: 'hide', el: env }, { type: 'reset' });
  const ease = u => u < .5 ? 4 * u * u * u : 1 - Math.pow(-2 * u + 2, 3) / 2;
  let i = 0, t = 0, last = 0, running = true, visible = true, raf = 0;
  const reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const step = now => {
    raf = 0; if (!running || !visible) return;
    const dt = last ? Math.min(0.3, (now - last) / 1000) : 0; last = now;
    let guard = 0;
    while (guard++ < 12) {
      const g = seq[i];
      if (g.type === 'show') { g.el.setAttribute('visibility', 'visible'); i++; continue; }
      if (g.type === 'hide') { g.el.setAttribute('visibility', 'hidden'); i++; continue; }
      if (g.type === 'reset') { place(pod, route.getPointAtLength(nearest(route, 410, 380))); i = 0; t = 0; continue; }
      if (g.type === 'dwell') { if (t === 0) setStop(g.stop); t += dt; if (t >= g.t) { i++; t = 0; continue; } break; }
      if (g.type === 'move') {
        if (t === 0 && g.stop) setStop(g.stop);
        const dur = Math.max(0.6, Math.abs(g.b - g.a) / g.speed);
        t += dt; const u = Math.min(1, t / dur);
        place(g.el, g.path.getPointAtLength(g.a + (g.b - g.a) * ease(u)));
        if (u >= 1) { i++; t = 0; continue; }
        break;
      }
    }
    raf = requestAnimationFrame(step);
  };
  const kick = () => { if (!raf && running && visible) { last = 0; raf = requestAnimationFrame(step); } };
  const label = () => { btn.textContent = running ? 'Pause tour' : 'Play tour'; btn.setAttribute('aria-pressed', String(running)); };
  btn.addEventListener('click', () => { running = !running; label(); kick(); });
  if (reduce) { running = false; label(); }
  if ('IntersectionObserver' in window) {
    new IntersectionObserver(es => { visible = es[0].isIntersecting; kick(); }, { threshold: 0.05 }).observe($('map'));
  }
  kick();
})();
</script>
`;

writeFileSync(OUT, HTML);
console.log('wrote', OUT, (HTML.length / 1024).toFixed(0) + ' KB');

// local preview copy with the skeleton the publisher adds
writeFileSync(join(here, 'preview.html'), '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"><style>body{margin:0}</style></head><body>' + HTML + '</body></html>');
