/* 运行时探测与平台实现加载。
   Node 与 Workers 的唯一差别都收在 platform/{node,workers}.js 里，
   上层 api/* 与入口 src/index.js 完全共用一套代码。 */

/** Workers 里 navigator.userAgent 固定为 Cloudflare-Workers；Node 22 也有 navigator，但值不同 */
export const isWorkers = globalThis.navigator?.userAgent === 'Cloudflare-Workers';

let impl = null;

/** 取当前运行时的平台实现（首次调用时按需加载） */
export async function platform() {
  if (impl) return impl;
  impl = isWorkers ? (await import('./workers.js')).default : (await import('./node.js')).default;
  return impl;
}
