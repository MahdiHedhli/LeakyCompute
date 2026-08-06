addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

const KV = await CKVNamespace.get('research_exposure') // private KV namespace

async function handleRequest(request) {
  const url = new URL(request.url)

  if (url.pathname === '/stats') {
    const summary = JSON.parse(await KV.get('latest_summary') || '{}')
    return new Response(JSON.stringify(summary), {
      headers: { 'Content-Type': 'application/json' }
    })
  }

  return new Response('Not found', { status: 404 })
}