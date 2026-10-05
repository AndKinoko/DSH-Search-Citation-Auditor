/**
 * 告警块的每次检测随机标记。
 *
 * 用途：分隔符不能用固定常量。攻击页面只要原样复制那条分隔线，就能在真告警之后
 * 再伪造一条结构同构的假横幅，而模型刚被告知「以下内容来自不可信网页」，伪造那条
 * 离攻击者自己的指令更近。随机 nonce 让伪造方事先看不到分隔符，无法预先构造。
 *
 * 用 crypto 而非 Math.random：这不是密码学用途，但宿主环境里 crypto.getRandomValues
 * 始终可得，而 Math.random 在某些精简宿主里可能被宿主自身降级或替换。
 * 取不到时退回时间戳——此时仍优于固定常量。
 */

const ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"; // 去掉易混的 I/L/O/0/1

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  const c: Crypto | undefined = typeof globalThis.crypto !== "undefined" ? globalThis.crypto : undefined;
  if (c !== undefined && typeof c.getRandomValues === "function") {
    c.getRandomValues(out);
    return out;
  }
  for (let i = 0; i < n; i++) out[i] = Math.floor(Math.random() * 256);
  return out;
}

/** 生成形如 `K7QX-2M4B` 的短标记。 */
export function nonceOf(): string {
  const bytes = randomBytes(8);
  let s = "";
  for (let i = 0; i < bytes.length; i++) {
    s += ALPHABET[(bytes[i] as number) % ALPHABET.length];
    if (i === 3) s += "-";
  }
  return s;
}