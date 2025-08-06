"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ParsingEngine = ParsingEngine;
const error_1 = require("./error");
function ParsingEngine() {
    const parsers = [];
    return {
        register(parser) {
            parsers.push(parser);
        },
        async parse({ rawCredential }) {
            for (const p of parsers) {
                const result = await p.parse({ rawCredential });
                if (result.success) {
                    return result;
                }
            }
            return {
                success: false,
                error: error_1.CredentialParsingError.CouldNotParse
            };
        }
    };
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiUGFyc2luZ0VuZ2luZS5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uL3NyYy9QYXJzaW5nRW5naW5lLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7O0FBSUEsc0NBdUJDO0FBM0JELG1DQUFpRDtBQUlqRCxTQUFnQixhQUFhO0lBQzVCLE1BQU0sT0FBTyxHQUF1QixFQUFFLENBQUM7SUFFdkMsT0FBTztRQUNOLFFBQVEsQ0FBQyxNQUF3QjtZQUNoQyxPQUFPLENBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFDO1FBQ3RCLENBQUM7UUFFRCxLQUFLLENBQUMsS0FBSyxDQUFDLEVBQUUsYUFBYSxFQUE4QjtZQUV4RCxLQUFLLE1BQU0sQ0FBQyxJQUFJLE9BQU8sRUFBRSxDQUFDO2dCQUN6QixNQUFNLE1BQU0sR0FBRyxNQUFNLENBQUMsQ0FBQyxLQUFLLENBQUMsRUFBRSxhQUFhLEVBQUUsQ0FBQyxDQUFDO2dCQUNoRCxJQUFJLE1BQU0sQ0FBQyxPQUFPLEVBQUUsQ0FBQztvQkFDcEIsT0FBTyxNQUFNLENBQUM7Z0JBQ2YsQ0FBQztZQUNGLENBQUM7WUFDRCxPQUFPO2dCQUNOLE9BQU8sRUFBRSxLQUFLO2dCQUNkLEtBQUssRUFBRSw4QkFBc0IsQ0FBQyxhQUFhO2FBQzNDLENBQUE7UUFFRixDQUFDO0tBQ0QsQ0FBQTtBQUNGLENBQUMifQ==