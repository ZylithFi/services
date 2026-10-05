export type PrivacyPoolAction = {
  variant: number;
  recipient?: string;
  token?: string;
  amount?: bigint;
  target?: string;
  calldata?: string[];
  noteId?: string;
};

export function parsePrivacyPoolActions(
  rawCalldata: string[],
  normalize: (value: string) => string
): PrivacyPoolAction[] | null {
  let calldata: string[];
  try {
    calldata = rawCalldata.map(normalize);
  } catch {
    return null;
  }
  if (calldata.length === 0) return null;
  const count = safeNumber(calldata[0]);
  if (count === null || count > 256) return null;
  const actions: PrivacyPoolAction[] = [];
  let offset = 1;
  for (let index = 0; index < count; index += 1) {
    const variant = safeNumber(calldata[offset]);
    if (variant === null || variant > 11) return null;
    if (variant === 0) {
      const spanLength = safeNumber(calldata[offset + 2]);
      if (spanLength === null) return null;
      actions.push({ variant });
      offset += 3 + spanLength;
    } else if (variant === 1) {
      actions.push({ variant });
      offset += 5;
    } else if (variant === 2 || variant === 3) {
      if (offset + 3 >= calldata.length) return null;
      if (variant === 2) {
        actions.push({
          variant,
          recipient: calldata[offset + 1]!,
          token: calldata[offset + 2]!,
          amount: BigInt(calldata[offset + 3]!),
        });
      } else {
        actions.push({ variant });
      }
      offset += 4;
    } else if (variant === 4) {
      if (offset + 5 >= calldata.length) return null;
      actions.push({ variant });
      offset += 6;
    } else if (variant === 5) {
      actions.push({ variant });
      offset += 7;
    } else if (variant === 6) {
      actions.push({ variant });
      offset += 4;
    } else if (variant === 7) {
      if (offset + 5 >= calldata.length) return null;
      actions.push({
        variant,
        token: calldata[offset + 4]!,
        noteId: calldata[offset + 5]!,
      });
      offset += 6;
    } else if (variant === 8) {
      actions.push({ variant });
      offset += 3;
    } else if (variant === 9) {
      actions.push({ variant });
      offset += 2;
    } else {
      const spanLength = safeNumber(calldata[offset + 2]);
      if (spanLength === null || offset + 3 + spanLength > calldata.length) return null;
      actions.push({
        variant,
        target: calldata[offset + 1]!,
        calldata: calldata.slice(offset + 3, offset + 3 + spanLength),
      });
      offset += 3 + spanLength;
    }
    if (offset > calldata.length) return null;
  }
  return validScreeningSuffix(calldata, offset) ? actions : null;
}

function safeNumber(value: string | undefined): number | null {
  if (value === undefined) return null;
  try {
    const parsed = BigInt(value);
    return parsed >= 0n && parsed <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(parsed) : null;
  } catch {
    return null;
  }
}

function validScreeningSuffix(calldata: string[], offset: number): boolean {
  if (offset === calldata.length) return true;
  const variant = safeNumber(calldata[offset]);
  return (variant === 1 && offset + 1 === calldata.length)
    || (variant === 0 && offset + 4 === calldata.length);
}
