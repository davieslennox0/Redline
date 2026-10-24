// Tiny Solidity / diff highlighter. Everything is HTML-escaped first; spans are added after.
export function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

const KW = new Set(("pragma import contract interface library function modifier constructor event error " +
  "struct enum mapping public private internal external view pure payable returns return if else for " +
  "while do require revert emit new is memory storage calldata immutable constant override virtual " +
  "unchecked receive fallback using assembly try catch").split(" "));
const TY = new Set(("uint uint8 uint128 uint256 int int256 address bool bytes bytes32 string").split(" "));

export function solidity(code) {
  const re = /(\/\/[^\n]*|\/\*[\s\S]*?\*\/)|("(?:[^"\\\n]|\\.)*")|(\b0x[0-9a-fA-F]+\b|\b\d[\d_]*(?:e\d+)?\b)|([A-Za-z_]\w*)/g;
  let out = "", last = 0, m;
  while ((m = re.exec(code))) {
    out += esc(code.slice(last, m.index));
    last = re.lastIndex;
    if (m[1]) out += `<span class="tk-c">${esc(m[1])}</span>`;
    else if (m[2]) out += `<span class="tk-s">${esc(m[2])}</span>`;
    else if (m[3]) out += `<span class="tk-n">${esc(m[3])}</span>`;
    else if (KW.has(m[4])) out += `<span class="tk-k">${esc(m[4])}</span>`;
    else if (TY.has(m[4]) || /^[A-Z]\w*$/.test(m[4])) out += `<span class="tk-t">${esc(m[4])}</span>`;
    else out += esc(m[4]);
  }
  return out + esc(code.slice(last));
}

export function diff(text) {
  return String(text ?? "").split("\n").map((l) => {
    const cls = l.startsWith("+++") || l.startsWith("---") ? "df-h" :
      l.startsWith("+") ? "df-a" : l.startsWith("-") ? "df-d" : l.startsWith("@@") ? "df-h" : "";
    return `<span class="${cls}">${esc(l)}</span>`;
  }).join("\n");
}
