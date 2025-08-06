"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.matchDisplayByLang = matchDisplayByLang;
exports.matchDisplayByLocale = matchDisplayByLocale;
function matchDisplayByLang(arr, preferredLangs) {
    if (!Array.isArray(arr))
        return null;
    for (const lang of preferredLangs) {
        const match = arr.find(d => d.lang === lang ||
            d.lang?.startsWith(lang + '-') ||
            lang?.startsWith(d.lang + '-'));
        if (match)
            return match;
    }
    return arr[0] ?? null;
}
function matchDisplayByLocale(arr, preferredLangs) {
    if (!Array.isArray(arr))
        return null;
    for (const lang of preferredLangs) {
        const match = arr.find(d => d.locale === lang ||
            d.locale?.startsWith(lang + '-') ||
            lang?.startsWith(d.locale + '-'));
        if (match)
            return match;
    }
    return arr[0] ?? null;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoibWF0Y2hMb2NhbGl6ZWREaXNwbGF5LmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3V0aWxzL21hdGNoTG9jYWxpemVkRGlzcGxheS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOztBQUdBLGdEQWVDO0FBRUQsb0RBZUM7QUFoQ0QsU0FBZ0Isa0JBQWtCLENBQ2pDLEdBQW9CLEVBQ3BCLGNBQXdCO0lBRXhCLElBQUksQ0FBQyxLQUFLLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQztRQUFFLE9BQU8sSUFBSSxDQUFDO0lBRXJDLEtBQUssTUFBTSxJQUFJLElBQUksY0FBYyxFQUFFLENBQUM7UUFDbkMsTUFBTSxLQUFLLEdBQUcsR0FBRyxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUMxQixDQUFDLENBQUMsSUFBSSxLQUFLLElBQUk7WUFDZixDQUFDLENBQUMsSUFBSSxFQUFFLFVBQVUsQ0FBQyxJQUFJLEdBQUcsR0FBRyxDQUFDO1lBQzlCLElBQUksRUFBRSxVQUFVLENBQUMsQ0FBQyxDQUFDLElBQUksR0FBRyxHQUFHLENBQUMsQ0FDOUIsQ0FBQztRQUNGLElBQUksS0FBSztZQUFFLE9BQU8sS0FBSyxDQUFDO0lBQ3pCLENBQUM7SUFDRCxPQUFPLEdBQUcsQ0FBQyxDQUFDLENBQUMsSUFBSSxJQUFJLENBQUM7QUFDdkIsQ0FBQztBQUVELFNBQWdCLG9CQUFvQixDQUNuQyxHQUFvQixFQUNwQixjQUF3QjtJQUV4QixJQUFJLENBQUMsS0FBSyxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUM7UUFBRSxPQUFPLElBQUksQ0FBQztJQUVyQyxLQUFLLE1BQU0sSUFBSSxJQUFJLGNBQWMsRUFBRSxDQUFDO1FBQ25DLE1BQU0sS0FBSyxHQUFHLEdBQUcsQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FDMUIsQ0FBQyxDQUFDLE1BQU0sS0FBSyxJQUFJO1lBQ2pCLENBQUMsQ0FBQyxNQUFNLEVBQUUsVUFBVSxDQUFDLElBQUksR0FBRyxHQUFHLENBQUM7WUFDaEMsSUFBSSxFQUFFLFVBQVUsQ0FBQyxDQUFDLENBQUMsTUFBTSxHQUFHLEdBQUcsQ0FBQyxDQUNoQyxDQUFDO1FBQ0YsSUFBSSxLQUFLO1lBQUUsT0FBTyxLQUFLLENBQUM7SUFDekIsQ0FBQztJQUNELE9BQU8sR0FBRyxDQUFDLENBQUMsQ0FBQyxJQUFJLElBQUksQ0FBQztBQUN2QixDQUFDIn0=