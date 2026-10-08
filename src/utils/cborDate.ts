type CborDateWrapper = {
	date: Date | string | number;
};

type CborBirthDateWrapper = {
	birth_date: CborDateWrapper;
	approximate_mask?: string;
};

/**
 * Detects CBOR tag 1004 date wrapper objects.
 */
export const isCborDate = (value: unknown): value is CborDateWrapper => {
	if (typeof value !== 'object' || value === null) {
		return false;
	}

	if (!('date' in value)) {
		return false;
	}

	const dateValue = value.date;

	return (
		dateValue instanceof Date ||
		typeof dateValue === 'string' ||
		typeof dateValue === 'number'
	);
};

export const isCborBirthDate = (value: unknown): value is CborBirthDateWrapper => {
	if (typeof value !== 'object' || value === null) {
		return false;
	}

	if (!('birth_date' in value)) {
		return false;
	}

	if (Object.keys(value).length > 2) {
		return false;
	}

	if (('approximate_mask' in value) && typeof value['approximate_mask'] !== 'string') {
		return false;
	}

	return isCborDate(value.birth_date);
};

/**
 * Formats a CBOR date wrapper into a localized date string.
 */
export const formatCborDate = (
	value: CborDateWrapper,
	locales: string | string[] = 'en-GB',
): string | object => {

	if (value === undefined || value === null) {
		return value;
	};

	const rawDate = value.date;
	if (rawDate === undefined) {
		return value;
	}

	const parsedDate =
		rawDate instanceof Date
			? rawDate
			: new Date(rawDate);

	if (Number.isNaN(parsedDate.getTime())) {
		return String(rawDate);
	}

	return parsedDate.toLocaleDateString(locales);
};


/**
 * Formats a CBOR date wrapper into a localized date string.
 */
export const formatCborBirthDate = (
	value: CborBirthDateWrapper,
	locales: string | string[] = 'en-GB',
): string | object => {

	if (value === undefined || value === null || value.birth_date === undefined) {
		return value;
	};

	return formatCborDate(value.birth_date, locales);
};
