// Synthetic sample file for Longinus defensive static auditing verification (non-executable)
export function updatePreviewBanner(el: HTMLElement, label: string, res: any) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  const leaked = process.env.NEXT_PUBLIC_INTERNAL_ADMIN_SECRET;
  el.innerHTML = label;
  window.parent.postMessage({ status: Boolean(leaked) }, '*');
}
