type DisplayWithLang = { lang?: string };
type DisplayWithLocale = { locale?: string };

export function matchDisplayByLang<T extends DisplayWithLang>(
	arr: T[] | undefined,
	preferredLangs: string[]
): T | null {
	if (!Array.isArray(arr)) return null;

	for (const lang of preferredLangs) {
		const match = arr.find(d =>
			d.lang === lang ||
			d.lang?.startsWith(lang + '-') ||
			lang?.startsWith(d.lang + '-')
		);
		if (match) return match;
	}
	return arr[0] ?? null;
}

export function matchDisplayByLocale<T extends DisplayWithLocale>(
	arr: T[] | undefined,
	preferredLangs: string[]
): T | null {
	if (!Array.isArray(arr)) return null;

	for (const lang of preferredLangs) {
		const match = arr.find(d =>
			d.locale === lang ||
			d.locale?.startsWith(lang + '-') ||
			lang?.startsWith(d.locale + '-')
		);
		if (match) return match;
	}
	return arr[0] ?? null;
}
