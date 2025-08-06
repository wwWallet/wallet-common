"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.formatDate = formatDate;
function formatDate(value, format = 'datetime') {
    // Regex for ISO 8601 format like '2024-10-08T07:28:49.117Z'
    const iso8601Regex = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z$/;
    // Regex for simple YYYY-MM-DD format
    const simpleDateRegex = /^\d{4}-\d{2}-\d{2}$/;
    // Regex for long-form date strings like 'Wed Dec 11 2024 14:46:19 GMT+0200'
    const longFormDateRegex = /^[A-Z][a-z]{2} [A-Z][a-z]{2} \d{2} \d{4} \d{2}:\d{2}:\d{2} GMT[+-]\d{4}/;
    let date;
    if (typeof value === 'number' && value.toString().length === 10) {
        // Handle Unix timestamp (seconds) by converting to milliseconds
        date = new Date(value * 1000);
    }
    else if (typeof value === 'string') {
        if (iso8601Regex.test(value)) {
            // Handle ISO 8601 format
            date = new Date(value);
        }
        else if (simpleDateRegex.test(value)) {
            // Handle YYYY-MM-DD format
            date = new Date(value);
        }
        else if (longFormDateRegex.test(value)) {
            // Handle long-form date string
            date = new Date(value);
        }
        else {
            // Non-date strings, including IDs, are returned as-is
            return value;
        }
    }
    else if (value instanceof Date) {
        // Handle Date objects directly
        date = value;
    }
    else {
        // For unsupported types, return the original value
        return value;
    }
    const options = format === 'datetime'
        ? { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' }
        : { day: '2-digit', month: '2-digit', year: 'numeric' };
    return date.toLocaleDateString('en-GB', options);
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZm9ybWF0RGF0ZS5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9mdW5jdGlvbnMvZm9ybWF0RGF0ZS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOztBQUFBLGdDQXdDQztBQXhDRCxTQUFnQixVQUFVLENBQUMsS0FBVSxFQUFFLE1BQU0sR0FBRyxVQUFVO0lBQ3pELDREQUE0RDtJQUM1RCxNQUFNLFlBQVksR0FBRyw4Q0FBOEMsQ0FBQztJQUNwRSxxQ0FBcUM7SUFDckMsTUFBTSxlQUFlLEdBQUcscUJBQXFCLENBQUM7SUFDOUMsNEVBQTRFO0lBQzVFLE1BQU0saUJBQWlCLEdBQUcseUVBQXlFLENBQUM7SUFFcEcsSUFBSSxJQUFJLENBQUM7SUFFVCxJQUFJLE9BQU8sS0FBSyxLQUFLLFFBQVEsSUFBSSxLQUFLLENBQUMsUUFBUSxFQUFFLENBQUMsTUFBTSxLQUFLLEVBQUUsRUFBRSxDQUFDO1FBQ2pFLGdFQUFnRTtRQUNoRSxJQUFJLEdBQUcsSUFBSSxJQUFJLENBQUMsS0FBSyxHQUFHLElBQUksQ0FBQyxDQUFDO0lBQy9CLENBQUM7U0FBTSxJQUFJLE9BQU8sS0FBSyxLQUFLLFFBQVEsRUFBRSxDQUFDO1FBQ3RDLElBQUksWUFBWSxDQUFDLElBQUksQ0FBQyxLQUFLLENBQUMsRUFBRSxDQUFDO1lBQzlCLHlCQUF5QjtZQUN6QixJQUFJLEdBQUcsSUFBSSxJQUFJLENBQUMsS0FBSyxDQUFDLENBQUM7UUFDeEIsQ0FBQzthQUFNLElBQUksZUFBZSxDQUFDLElBQUksQ0FBQyxLQUFLLENBQUMsRUFBRSxDQUFDO1lBQ3hDLDJCQUEyQjtZQUMzQixJQUFJLEdBQUcsSUFBSSxJQUFJLENBQUMsS0FBSyxDQUFDLENBQUM7UUFDeEIsQ0FBQzthQUFNLElBQUksaUJBQWlCLENBQUMsSUFBSSxDQUFDLEtBQUssQ0FBQyxFQUFFLENBQUM7WUFDMUMsK0JBQStCO1lBQy9CLElBQUksR0FBRyxJQUFJLElBQUksQ0FBQyxLQUFLLENBQUMsQ0FBQztRQUN4QixDQUFDO2FBQU0sQ0FBQztZQUNQLHNEQUFzRDtZQUN0RCxPQUFPLEtBQUssQ0FBQztRQUNkLENBQUM7SUFDRixDQUFDO1NBQU0sSUFBSSxLQUFLLFlBQVksSUFBSSxFQUFFLENBQUM7UUFDbEMsK0JBQStCO1FBQy9CLElBQUksR0FBRyxLQUFLLENBQUM7SUFDZCxDQUFDO1NBQU0sQ0FBQztRQUNQLG1EQUFtRDtRQUNuRCxPQUFPLEtBQUssQ0FBQztJQUNkLENBQUM7SUFFRCxNQUFNLE9BQU8sR0FBRyxNQUFNLEtBQUssVUFBVTtRQUNwQyxDQUFDLENBQUMsRUFBRSxHQUFHLEVBQUUsU0FBUyxFQUFFLEtBQUssRUFBRSxTQUFTLEVBQUUsSUFBSSxFQUFFLFNBQVMsRUFBRSxJQUFJLEVBQUUsU0FBUyxFQUFFLE1BQU0sRUFBRSxTQUFTLEVBQUUsTUFBTSxFQUFFLFNBQVMsRUFBRTtRQUM5RyxDQUFDLENBQUMsRUFBRSxHQUFHLEVBQUUsU0FBUyxFQUFFLEtBQUssRUFBRSxTQUFTLEVBQUUsSUFBSSxFQUFFLFNBQVMsRUFBRSxDQUFDO0lBRXpELE9BQU8sSUFBSSxDQUFDLGtCQUFrQixDQUFDLE9BQU8sRUFBRSxPQUFjLENBQUMsQ0FBQztBQUN6RCxDQUFDIn0=