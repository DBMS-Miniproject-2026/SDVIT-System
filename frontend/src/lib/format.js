export const fmtScore = (v, digits = 1) =>
  v === null || v === undefined || v === "" ? "—" : Number(v).toFixed(digits);

export const fmtDate = (v) => {
  if (!v) return "—";
  const s = String(v);
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s;           // DATE columns arrive as plain strings
  const d = new Date(s.includes("T") ? s : s.replace(" ", "T"));
  return Number.isNaN(d.getTime()) ? s.slice(0, 10) : d.toLocaleDateString();
};

export const fmtDateTime = (v) => {
  if (!v) return "—";
  const d = new Date(String(v).includes("T") ? v : String(v).replace(" ", "T"));
  return Number.isNaN(d.getTime()) ? String(v) : d.toLocaleString();
};

export const apiError = (e, fallback) => e?.response?.data?.message || fallback;
