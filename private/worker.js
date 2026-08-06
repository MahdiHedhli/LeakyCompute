addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

const KV = await CKVNamespace.get('research_exposure') // private KV namespace

async function handleRequest(request) {
  const url = new URL(request.url)

  // --------------------------------------------------------------
  //  /check?ip=...   → single‑IP check (public‑facing)
  // --------------------------------------------------------------
  if (url.searchParams.has('ip')) {
    const ip = url.searchParams.get('ip')
    const result = await checkOne(ip)
    // store for later stats
    await KV.put(`exposure:${ip}`, JSON.stringify(result))
    return new Response(JSON.stringify(result), {
      headers: { 'Content-Type': 'application/json' }
    })
  }

  // --------------------------------------------------------------
  //  /bulk  → POST body = { "cidrs": ["10.0.0.0/8", "192.168.1.0/24"] }
  // --------------------------------------------------------------
  if (url.pathname === '/bulk' && request.method === 'POST') {
    const { cidrs } = await request.json()
    const results = await runBulkScan(cidrs)
    const summary = await aggregateSummary(results)
    // persist a compact summary for stats
    await KV.put('latest_summary', JSON.stringify(summary))
    return new Response(JSON.stringify(results), {
      headers: { 'Content-Type': 'application/json' }
    })
  }

  return new Response('Not found', { status: 404 })
}

// --------------------------------------------------------------
//  Single‑IP check (uses direct HTTP request; you could replace with MCP call if desired)
// --------------------------------------------------------------
async function checkOne(ip) {
  try {
    const resp = await fetch(`http://${ip}:11434/api/ps`, {
      method: 'GET',
      headers: { 'Authorization': 'Bearer ${{ secrets.OLLAMA_TOKEN }}' },
      redirect: 'manual',
      timeout: 5
    })
    if (resp.ok) {
      const data = await resp.json()
      return { ip, exposed: true, models: data.models }
    }
  } catch (e) {
    // any error => not exposed
  }
  return { ip, exposed: false, models: [] }
}

// --------------------------------------------------------------
//  Bulk scan – iterate over a list of CIDRs
// --------------------------------------------------------------
async function runBulkScan(cidrList) {
  const results = []
  for (const cidr of cidrList) {
    const ips = await ipRange(cidr)   // helper that expands CIDR → array of IPs
    for (const ip of ips) {
      const r = await checkOne(ip)
      results.push(r)
    }
  }
  return results
}

// CIDR expansion helper (IPv4 only)
async function ipRange(cidr) {
  const [addr, mask] = cidr.split('/')
  const start = ipToInt(addr)
  const end = start + (1 << (32 - mask)) - 1
  const ips = []
  for (let i = start; i <= end; i++) ips.push(intToIp(i))
  return ips
}

function ipToInt(ip) {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + Number(octet), 0)
}
function intToIp(int) {
  return [
    (int >>> 24) & 255,
    (int >>> 16) & 255,
    (int >>> 8) & 255,
    int & 255
  ].join('.')
}

async function aggregateSummary(results) {
  const summary = { total: 0, exposed: 0, models: {} }
  for (const r of results) {
    summary.total++
    if (r.exposed) summary.exposed++
    if (r.models) {
      r.models.forEach(m => {
        summary.models[m] = (summary.models[m] || 0) + 1
      })
    }
  }
  return summary
}