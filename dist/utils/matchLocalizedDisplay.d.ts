type DisplayWithLang = {
    lang?: string;
};
type DisplayWithLocale = {
    locale?: string;
};
export declare function matchDisplayByLang<T extends DisplayWithLang>(arr: T[] | undefined, preferredLangs: string[]): T | null;
export declare function matchDisplayByLocale<T extends DisplayWithLocale>(arr: T[] | undefined, preferredLangs: string[]): T | null;
export {};
//# sourceMappingURL=matchLocalizedDisplay.d.ts.map