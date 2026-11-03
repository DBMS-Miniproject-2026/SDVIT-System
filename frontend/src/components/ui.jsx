import React, { useEffect } from "react";
import { AlertTriangle, ShieldCheck, X } from "lucide-react";

export function severityClass(severity = "") {
  return `severity severity-${severity.toLowerCase()}`;
}

export function StatusPill({ status }) {
  return <span className={`status status-${String(status || "").toLowerCase()}`}>{status}</span>;
}

export function SeverityPill({ severity }) {
  return (
    <span className={severityClass(severity)}>
      <span className="severity-dot" />
      {severity || "Unknown"}
    </span>
  );
}

export function ErrorState({ message, retry }) {
  return (
    <div className="error-state">
      <AlertTriangle size={20} />
      <div>
        <strong>Unable to complete the request</strong>
        <p>{message}</p>
      </div>
      {retry && (
        <button className="button button-quiet" onClick={retry}>
          Retry
        </button>
      )}
    </div>
  );
}

export function EmptyState({ message }) {
  return (
    <div className="empty-state">
      <ShieldCheck size={26} />
      <p>{message}</p>
    </div>
  );
}

export function PageHeading({ eyebrow, title, description, action }) {
  return (
    <div className="page-heading">
      <div>
        <div className="eyebrow">{eyebrow}</div>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {action && <div className="heading-actions">{action}</div>}
    </div>
  );
}

export function MetricCard({ label, value, detail, icon: Icon, tone = "cyan" }) {
  return (
    <div className="metric-card">
      <div className="metric-top">
        <span>{label}</span>
        <span className={`metric-icon ${tone}`}>
          <Icon size={18} />
        </span>
      </div>
      <div className="metric-value">{Number(value || 0).toLocaleString()}</div>
      <div className="metric-detail">{detail}</div>
    </div>
  );
}

export function DataTable({ columns, rows, rowKey, emptyMessage = "No records found." }) {
  if (!rows?.length) return <EmptyState message={emptyMessage} />;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key}>{c.label}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={rowKey ? rowKey(row) : row.id || i}>
              {columns.map((c) => (
                <td key={c.key}>{c.render ? c.render(row) : (row[c.key] ?? "—")}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// Small label that names the database object feeding a panel or button.
export function SqlTag({ kind, name }) {
  return (
    <span className="sql-tag" title={`${kind} ${name}`}>
      <b>{kind}</b> {name}
    </span>
  );
}

export function Modal({ title, subtitle, onClose, children, wide = false }) {
  useEffect(() => {
    const onKey = (e) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <div
        className={wide ? "modal modal-wide" : "modal"}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="modal-head">
          <div>
            <h2>{title}</h2>
            {subtitle && <p>{subtitle}</p>}
          </div>
          <button className="icon-button" onClick={onClose} aria-label="Close">
            <X size={16} />
          </button>
        </div>
        <div className="modal-body">{children}</div>
      </div>
    </div>
  );
}

export function Field({ label, children, hint }) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
      {hint && <small>{hint}</small>}
    </label>
  );
}

// Banner that reports what the database did in response to an action
// (for example which trigger fired and how many alerts it created).
export function DbNotice({ notice, onDismiss }) {
  if (!notice) return null;
  return (
    <div className={`db-notice ${notice.tone || "ok"}`}>
      <div>
        <strong>{notice.title}</strong>
        {notice.lines?.map((l, i) => (
          <p key={i}>{l}</p>
        ))}
      </div>
      <button className="icon-button" onClick={onDismiss} aria-label="Dismiss">
        <X size={14} />
      </button>
    </div>
  );
}

export function PackageVersionSelect({ packages, value, onChange, placeholder = "Select package version" }) {
  return (
    <select value={value} onChange={(e) => onChange(e.target.value)} required>
      <option value="">{placeholder}</option>
      {packages.map((p) => (
        <optgroup key={p.id} label={`${p.name} (${p.ecosystem})`}>
          {p.versions.map((v) => (
            <option key={v.id} value={v.id}>
              {p.name} {v.version}
            </option>
          ))}
        </optgroup>
      ))}
    </select>
  );
}
