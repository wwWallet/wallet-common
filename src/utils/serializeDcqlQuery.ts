/**
 * removes _ underscore
 * @param obj
 * @returns
 */
export function serializeDcqlQuery(obj: any): any {
	if (Array.isArray(obj)) {
		return obj.map(serializeDcqlQuery);
	} else if (obj !== null && typeof obj === 'object') {
		return Object.fromEntries(
			Object.entries(obj)
				.filter(([key, _]) => !key.startsWith('_'))
				.map(([key, value]) => [key, serializeDcqlQuery(value)])
		);
	}
	return obj;
}
