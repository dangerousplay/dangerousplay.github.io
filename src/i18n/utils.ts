import { ui, languages, type Lang, type UiKey } from './ui';

export { type Lang, languages };

export function getLangFromUrl(url: URL): Lang {
  const [, maybeLang] = url.pathname.split('/');
  if (maybeLang === 'pt') return 'pt';
  return 'en';
}

/** Returns a typed translation function for the given language. */
export function useTranslations(lang: Lang) {
  return function t(key: UiKey): string {
    return (ui[lang] as Record<string, string>)[key] ?? (ui['en'] as Record<string, string>)[key];
  };
}

/**
 * Given the current language and pathname, return the equivalent pathname
 * in the other language.
 */
export function getAlternateLangUrl(lang: Lang, pathname: string): string {
  if (lang === 'en') {
    // Switch en → pt: prepend /pt
    return '/pt' + (pathname === '/' ? '/' : pathname);
  } else {
    // Switch pt → en: strip /pt prefix
    const stripped = pathname.replace(/^\/pt/, '') || '/';
    return stripped;
  }
}

/** Build a locale-aware internal URL. */
export function localePath(lang: Lang, path: string): string {
  if (lang === 'en') return path;
  // path should start with /
  return '/pt' + path;
}
