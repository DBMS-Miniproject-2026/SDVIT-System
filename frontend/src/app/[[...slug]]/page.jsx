"use client";

import dynamic from "next/dynamic";

const ClientRoot = dynamic(() => import("../../ClientRoot.jsx"), {
  ssr: false,
  loading: () => <div className="auth-loading">Loading SDVIT console…</div>,
});

export default function ApplicationPage() {
  return <ClientRoot />;
}
