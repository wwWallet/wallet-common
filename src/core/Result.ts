export type Result<T, E = Error> =
	| { ok: true; value: T }
	| { ok: false; error: E, error_description?: string };

export function ok<T>(value: T): Result<T, never> {
	return { ok: true, value };
}

export function err<E>(error: E, error_description?: string): Result<never, E> {
	return { ok: false, error, error_description };
}
