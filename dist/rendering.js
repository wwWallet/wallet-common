"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.CredentialRenderingService = CredentialRenderingService;
const jsonpointer_1 = __importDefault(require("jsonpointer"));
const formatDate_1 = require("./functions/formatDate");
const escapeSVG_1 = require("./utils/escapeSVG");
function CredentialRenderingService() {
    const renderSvgTemplate = async ({ json, credentialImageSvgTemplate, sdJwtVcMetadataClaims, filter }) => {
        let svgContent = null;
        try {
            svgContent = credentialImageSvgTemplate;
        }
        catch (error) {
            return null; // Return null if fetching fails
        }
        if (svgContent) {
            // Build pathMap from credentialHeader.vctm.claims
            const pathMap = sdJwtVcMetadataClaims.reduce((acc, claim) => {
                if (claim.svg_id && claim.path) {
                    acc[claim.svg_id] = claim.path;
                }
                return acc;
            }, {});
            // Regular expression to match {{svg_id}} placeholders
            const regex = /{{([^}]+)}}/g;
            const replacedSvgText = svgContent.replace(regex, (_match, svgId) => {
                // Retrieve the path array for the current svgId from pathMap
                const pathArray = pathMap[svgId];
                if (Array.isArray(pathArray) && filter && !filter.map(f => f.join('.')).includes(pathArray.join('.'))) {
                    return '-';
                }
                // If pathArray exists, convert it to a JSON pointer path
                if (Array.isArray(pathArray)) {
                    const jsonPointerPath = `/${pathArray.join('/')}`;
                    // Retrieve the value from beautifiedForm using jsonpointer
                    let value = (0, escapeSVG_1.escapeSVG)(jsonpointer_1.default.get(json, jsonPointerPath));
                    if (value !== undefined) {
                        value = (0, formatDate_1.formatDate)(value, 'date');
                        return value;
                    }
                }
                return '-';
            });
            const dataUri = `data:image/svg+xml;utf8,${encodeURIComponent(replacedSvgText)}`;
            return dataUri; // Return the data URI for the SVG
        }
        return null;
    };
    return {
        renderSvgTemplate,
    };
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoicmVuZGVyaW5nLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vc3JjL3JlbmRlcmluZy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7OztBQU1BLGdFQW9EQztBQTFERCw4REFBc0M7QUFDdEMsdURBQW9EO0FBRXBELGlEQUE4QztBQUc5QyxTQUFnQiwwQkFBMEI7SUFDekMsTUFBTSxpQkFBaUIsR0FBRyxLQUFLLEVBQUUsRUFBRSxJQUFJLEVBQUUsMEJBQTBCLEVBQUUscUJBQXFCLEVBQUUsTUFBTSxFQUFzSCxFQUFFLEVBQUU7UUFFM04sSUFBSSxVQUFVLEdBQUcsSUFBSSxDQUFDO1FBQ3RCLElBQUksQ0FBQztZQUNKLFVBQVUsR0FBRywwQkFBMEIsQ0FBQztRQUN6QyxDQUFDO1FBQUMsT0FBTyxLQUFLLEVBQUUsQ0FBQztZQUNoQixPQUFPLElBQUksQ0FBQyxDQUFDLGdDQUFnQztRQUM5QyxDQUFDO1FBRUQsSUFBSSxVQUFVLEVBQUUsQ0FBQztZQUNoQixrREFBa0Q7WUFDbEQsTUFBTSxPQUFPLEdBQUcscUJBQXFCLENBQUMsTUFBTSxDQUFDLENBQUMsR0FBUSxFQUFFLEtBQVUsRUFBRSxFQUFFO2dCQUNyRSxJQUFJLEtBQUssQ0FBQyxNQUFNLElBQUksS0FBSyxDQUFDLElBQUksRUFBRSxDQUFDO29CQUNoQyxHQUFHLENBQUMsS0FBSyxDQUFDLE1BQU0sQ0FBQyxHQUFHLEtBQUssQ0FBQyxJQUFJLENBQUM7Z0JBQ2hDLENBQUM7Z0JBQ0QsT0FBTyxHQUFHLENBQUM7WUFDWixDQUFDLEVBQUUsRUFBRSxDQUFDLENBQUM7WUFFUCxzREFBc0Q7WUFDdEQsTUFBTSxLQUFLLEdBQUcsY0FBYyxDQUFDO1lBQzdCLE1BQU0sZUFBZSxHQUFHLFVBQVUsQ0FBQyxPQUFPLENBQUMsS0FBSyxFQUFFLENBQUMsTUFBTSxFQUFFLEtBQUssRUFBRSxFQUFFO2dCQUNuRSw2REFBNkQ7Z0JBQzdELE1BQU0sU0FBUyxHQUFHLE9BQU8sQ0FBQyxLQUFLLENBQUMsQ0FBQztnQkFFakMsSUFBSSxLQUFLLENBQUMsT0FBTyxDQUFDLFNBQVMsQ0FBQyxJQUFJLE1BQU0sSUFBSSxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsUUFBUSxDQUFDLFNBQVMsQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLENBQUMsRUFBRSxDQUFDO29CQUN2RyxPQUFPLEdBQUcsQ0FBQztnQkFDWixDQUFDO2dCQUNELHlEQUF5RDtnQkFDekQsSUFBSSxLQUFLLENBQUMsT0FBTyxDQUFDLFNBQVMsQ0FBQyxFQUFFLENBQUM7b0JBQzlCLE1BQU0sZUFBZSxHQUFHLElBQUksU0FBUyxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsRUFBRSxDQUFDO29CQUVsRCwyREFBMkQ7b0JBQzNELElBQUksS0FBSyxHQUFHLElBQUEscUJBQVMsRUFBQyxxQkFBVyxDQUFDLEdBQUcsQ0FBQyxJQUFJLEVBQUUsZUFBZSxDQUFDLENBQUMsQ0FBQztvQkFFOUQsSUFBSSxLQUFLLEtBQUssU0FBUyxFQUFFLENBQUM7d0JBQ3pCLEtBQUssR0FBRyxJQUFBLHVCQUFVLEVBQUMsS0FBSyxFQUFFLE1BQU0sQ0FBQyxDQUFDO3dCQUNsQyxPQUFPLEtBQUssQ0FBQztvQkFDZCxDQUFDO2dCQUNGLENBQUM7Z0JBQ0QsT0FBTyxHQUFHLENBQUM7WUFDWixDQUFDLENBQUMsQ0FBQztZQUNILE1BQU0sT0FBTyxHQUFHLDJCQUEyQixrQkFBa0IsQ0FBQyxlQUFlLENBQUMsRUFBRSxDQUFDO1lBQ2pGLE9BQU8sT0FBTyxDQUFDLENBQUMsa0NBQWtDO1FBQ25ELENBQUM7UUFFRCxPQUFPLElBQUksQ0FBQztJQUNiLENBQUMsQ0FBQztJQUVGLE9BQU87UUFDTixpQkFBaUI7S0FDakIsQ0FBQTtBQUNGLENBQUMifQ==