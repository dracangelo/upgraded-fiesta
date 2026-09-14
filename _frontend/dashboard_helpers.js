/** @template T @param {T[] | null | undefined} value @returns {T[]} */
export function asList(value) {
  return Array.isArray(value) ? value : [];
}

