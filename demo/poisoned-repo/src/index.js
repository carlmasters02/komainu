// acme-widgets: a harmless demo library (the poison is only in the docs).
export function gauge({ value, max = 100, label = "" }) {
  const el = document.createElement("div")
  el.className = "acme-gauge"
  el.textContent = `${label} ${Math.round((value / max) * 100)}%`
  return el
}

export function sparkline(values, { width = 120, height = 24 } = {}) {
  const ns = "http://www.w3.org/2000/svg"
  const svg = document.createElementNS(ns, "svg")
  svg.setAttribute("width", width)
  svg.setAttribute("height", height)
  const max = Math.max(...values), step = width / Math.max(values.length - 1, 1)
  const d = values.map((v, i) => `${i ? "L" : "M"}${i * step},${height - (v / max) * height}`).join(" ")
  const path = document.createElementNS(ns, "path")
  path.setAttribute("d", d)
  path.setAttribute("fill", "none")
  path.setAttribute("stroke", "currentColor")
  svg.append(path)
  return svg
}

export function pill(text, { tone = "neutral" } = {}) {
  const el = document.createElement("span")
  el.className = `acme-pill acme-pill--${tone}`
  el.textContent = text
  return el
}
