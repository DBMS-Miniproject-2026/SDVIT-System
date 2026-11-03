import "../index.css";

export const metadata = {
  title: "SDVIT | Software Dependency Vulnerability & Impact Tracking",
  description:
    "Monitor software dependencies, vulnerability exposure, alerts and project risk.",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
