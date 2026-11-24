import { useEffect, useState } from "react";

export type ThemePreference = "system" | "light" | "dark";
export type ResolvedTheme = "light" | "dark";

const THEME_STORAGE_KEY = "domain_tools_theme_v1";

function readInitialPreference(): ThemePreference {
  try {
    const raw = localStorage.getItem(THEME_STORAGE_KEY);
    if (raw === "light" || raw === "dark" || raw === "system") {
      return raw;
    }
  } catch {
    // ignore storage errors
  }
  return "system";
}

function getMediaDark(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-color-scheme: dark)").matches
  );
}

function isTauriRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

function syncNativeWindowTheme(pref: ThemePreference): void {
  if (!isTauriRuntime()) return;
  void import("@tauri-apps/api/window")
    .then(({ getCurrentWindow }) => {
      const win = getCurrentWindow();
      return win.setTheme(pref === "system" ? null : pref);
    })
    .catch(() => {
      // ignore if unsupported by platform
    });
}

export function useTheme() {
  const [preference, setPreferenceState] = useState<ThemePreference>(
    readInitialPreference,
  );
  const [systemTheme, setSystemTheme] = useState<ResolvedTheme>(() =>
    getMediaDark() ? "dark" : "light",
  );

  const resolvedTheme: ResolvedTheme =
    preference === "system" ? systemTheme : preference;

  useEffect(() => {
    const root = document.documentElement;
    if (resolvedTheme === "dark") {
      root.classList.add("dark");
    } else {
      root.classList.remove("dark");
    }
  }, [resolvedTheme]);

  useEffect(() => {
    const media = window.matchMedia?.("(prefers-color-scheme: dark)");
    const onMediaChange = (e: MediaQueryListEvent) => {
      setSystemTheme(e.matches ? "dark" : "light");
    };
    media?.addEventListener("change", onMediaChange);

    let unlistenTauri: (() => void) | undefined;
    let active = true;

    if (isTauriRuntime()) {
      void import("@tauri-apps/api/window")
        .then(async ({ getCurrentWindow }) => {
          if (!active) return;
          const win = getCurrentWindow();
          if (preference === "system") {
            const nativeTheme = await win.theme().catch(() => null);
            if (active && (nativeTheme === "light" || nativeTheme === "dark")) {
              setSystemTheme(nativeTheme);
            }
          }
          unlistenTauri = await win.onThemeChanged(({ payload }) => {
            if (active && (payload === "light" || payload === "dark")) {
              setSystemTheme(payload);
            }
          });
        })
        .catch(() => {
          // fallback to CSS matchMedia
        });
    }

    return () => {
      active = false;
      media?.removeEventListener("change", onMediaChange);
      if (unlistenTauri) unlistenTauri();
    };
  }, [preference]);

  useEffect(() => {
    if (preference !== "system") {
      syncNativeWindowTheme(preference);
    }
  }, [preference]);

  const setPreference = (next: ThemePreference) => {
    setPreferenceState(next);
    try {
      localStorage.setItem(THEME_STORAGE_KEY, next);
    } catch {
      // ignore storage errors
    }
    syncNativeWindowTheme(next);
  };

  return { preference, setPreference, resolvedTheme };
}
