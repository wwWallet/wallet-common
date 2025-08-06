"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.OpenID4VCICredentialRendering = OpenID4VCICredentialRendering;
const escapeSVG_1 = require("../utils/escapeSVG");
const formatDate_1 = require("./formatDate");
function OpenID4VCICredentialRendering(args) {
    const defaultBackgroundColor = "#D3D3D3";
    const defaultTextColor = "#000000";
    const defaultName = "Credential";
    const svgTemplate = `<svg
			xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="829"
			height="504" version="1.1">
			<rect width="100%" height="100%" fill="{{backgroundColor}}" />
			{{backgroundImageBase64}}
			{{logoBase64}}
			<text x="50" y="80" font-family="Arial, Helvetica, sans-serif" font-size="35" fill="{{textColor}}" font-weight="normal">{{name}}</text>
			<text x="50" y="120" font-family="Arial, Helvetica, sans-serif" font-size="20" fill="{{textColor}}" font-weight="normal">{{description}}</text>
			<text x="790" y="431" text-anchor="end" font-family="Arial, Helvetica, sans-serif" font-size="25" fill="{{textColor}}" font-weight="normal">{{expiry_date}}</text>
		</svg>`;
    function formatExpiryDate(signedClaims) {
        if (signedClaims.expiry_date) {
            return (0, formatDate_1.formatDate)(signedClaims.expiry_date, 'date');
        }
        else if (signedClaims.exp != null) {
            const expiryDateISO = new Date(Number(signedClaims.exp) * 1000).toISOString();
            return (0, formatDate_1.formatDate)(expiryDateISO, 'date');
        }
        else {
            return "";
        }
    }
    async function getBase64Image(url) {
        if (!url)
            return null;
        try {
            const isBrowser = typeof window !== "undefined";
            if (isBrowser) {
                // Frontend: Use FileReader with Fetch API
                const response = await fetch(url);
                const blob = await response.blob();
                return new Promise((resolve, reject) => {
                    const reader = new FileReader();
                    reader.onloadend = () => resolve(reader.result);
                    reader.onerror = reject;
                    reader.readAsDataURL(blob);
                });
            }
            else {
                // Backend (Node.js): Use Axios or Fetch with Buffer
                const response = await args.httpClient.get(url, {}, { responseType: 'arraybuffer', useCache: true });
                const blob = response.data;
                const base64 = Buffer.from(blob, "binary").toString("base64");
                const mimeType = response.headers["content-type"]; // Get MIME type
                return `data:${mimeType};base64,${base64}`;
            }
        }
        catch (error) {
            console.error("Failed to load image", url, error);
            return null;
        }
    }
    const renderCustomSvgTemplate = async ({ signedClaims, displayConfig }) => {
        const name = displayConfig?.name ? (0, escapeSVG_1.escapeSVG)(displayConfig?.name) : defaultName;
        const description = displayConfig?.description ? (0, escapeSVG_1.escapeSVG)(displayConfig?.description) : "";
        const backgroundColor = displayConfig.backgroundColor || defaultBackgroundColor;
        const textColor = displayConfig.text_color || defaultTextColor;
        const backgroundImageBase64 = displayConfig?.background_image?.uri ?
            displayConfig?.background_image?.uri?.startsWith("data:") ?
                displayConfig?.background_image.uri
                : await getBase64Image(displayConfig?.background_image?.uri)
            : '';
        const logoBase64 = displayConfig?.logo?.uri ? await getBase64Image(displayConfig.logo.uri) : '';
        const expiryDate = formatExpiryDate(signedClaims);
        const replacedSvgText = svgTemplate
            .replace(/{{backgroundColor}}/g, backgroundColor)
            .replace(/{{backgroundImageBase64}}/g, backgroundImageBase64
            ? `<image xlink:href="${backgroundImageBase64}" x="0" y="0" width="100%" height="100%" preserveAspectRatio="xMidYMid slice" />`
            : '')
            .replace(/{{logoBase64}}/g, logoBase64
            ? `<image xlink:href="${logoBase64}" x="50" y="380" height="20%"><title>${displayConfig.logoAltText || 'Logo'}</title></image>`
            : '')
            .replace(/{{name}}/g, name)
            .replace(/{{textColor}}/g, textColor)
            .replace(/{{description}}/g, description)
            .replace(/{{expiry_date}}/g, expiryDate ? `Expiry Date: ${expiryDate}` : '');
        const dataUri = `data:image/svg+xml;utf8,${encodeURIComponent(replacedSvgText)}`;
        return dataUri;
    };
    return {
        renderCustomSvgTemplate,
    };
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib3BlbklENFZDSUNyZWRlbnRpYWxSZW5kZXJpbmcuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi9zcmMvZnVuY3Rpb25zL29wZW5JRDRWQ0lDcmVkZW50aWFsUmVuZGVyaW5nLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7O0FBS0Esc0VBc0dDO0FBekdELGtEQUErQztBQUMvQyw2Q0FBMEM7QUFFMUMsU0FBZ0IsNkJBQTZCLENBQUMsSUFBZ0M7SUFFN0UsTUFBTSxzQkFBc0IsR0FBRyxTQUFTLENBQUM7SUFDekMsTUFBTSxnQkFBZ0IsR0FBRyxTQUFTLENBQUM7SUFDbkMsTUFBTSxXQUFXLEdBQUcsWUFBWSxDQUFDO0lBQ2pDLE1BQU0sV0FBVyxHQUNoQjs7Ozs7Ozs7O1NBU08sQ0FBQTtJQUdSLFNBQVMsZ0JBQWdCLENBQUMsWUFBOEI7UUFDdkQsSUFBSSxZQUFZLENBQUMsV0FBVyxFQUFFLENBQUM7WUFDOUIsT0FBTyxJQUFBLHVCQUFVLEVBQUMsWUFBWSxDQUFDLFdBQVcsRUFBRSxNQUFNLENBQUMsQ0FBQztRQUNyRCxDQUFDO2FBQU0sSUFBSSxZQUFZLENBQUMsR0FBRyxJQUFJLElBQUksRUFBRSxDQUFDO1lBQ3JDLE1BQU0sYUFBYSxHQUFHLElBQUksSUFBSSxDQUFDLE1BQU0sQ0FBQyxZQUFZLENBQUMsR0FBRyxDQUFDLEdBQUcsSUFBSSxDQUFDLENBQUMsV0FBVyxFQUFFLENBQUM7WUFDOUUsT0FBTyxJQUFBLHVCQUFVLEVBQUMsYUFBYSxFQUFFLE1BQU0sQ0FBQyxDQUFDO1FBQzFDLENBQUM7YUFBTSxDQUFDO1lBQ1AsT0FBTyxFQUFFLENBQUM7UUFDWCxDQUFDO0lBQ0YsQ0FBQztJQUdELEtBQUssVUFBVSxjQUFjLENBQUMsR0FBVztRQUN4QyxJQUFJLENBQUMsR0FBRztZQUFFLE9BQU8sSUFBSSxDQUFDO1FBRXRCLElBQUksQ0FBQztZQUNKLE1BQU0sU0FBUyxHQUFHLE9BQU8sTUFBTSxLQUFLLFdBQVcsQ0FBQztZQUVo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