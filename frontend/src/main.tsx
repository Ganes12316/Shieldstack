import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import App from "./App.tsx";

function Router() {
  const [pathname, setPathname] = useState(window.location.pathname);

  useEffect(() => {
    const onPopState = () => setPathname(window.location.pathname);
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  const cleanPath = pathname.toLowerCase().replace(/\/+$/, "") || "/";
  if (cleanPath === "/") return <App />;
  return (
    <main className="not-found-page">
      <img src="/shieldstack-logo.png" alt="ShieldStack" />
      <p className="not-found-code">404</p>
      <h1>Page not found</h1>
      <p>The address may be incorrect or the page may have moved.</p>
      <a href="/">Return to ShieldStack</a>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <Router />
  </StrictMode>,
);
