// Light/dark: follow the system unless the user picked one (remembered on this device).
export type Theme = "auto" | "light" | "dark";
const STORAGE = "anubisauto-signer.theme";

export function storedTheme(): Theme {
  try {
    const value = localStorage.getItem(STORAGE);
    return value === "light" || value === "dark" ? value : "auto";
  } catch {
    return "auto";
  }
}

export function applyTheme(theme: Theme): void {
  const root = document.documentElement;
  if (theme === "auto") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", theme);
}

export function setTheme(theme: Theme): void {
  try {
    if (theme === "auto") localStorage.removeItem(STORAGE);
    else localStorage.setItem(STORAGE, theme);
  } catch {
    // Applies now even when it cannot be remembered.
  }
  applyTheme(theme);
}
