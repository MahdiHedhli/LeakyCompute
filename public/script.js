document.getElementById('checkBtn').addEventListener('click', async () => {
  const ip = document.getElementById('ipInput').value.trim();
  if (!ip) {
    alert('Please enter an IP address or CIDR.');
    return;
  }

  const response = await fetch('https://<YOUR_WORKER_SUBDOMAIN>.workers.dev/api/check?ip=' + ip)
    .then(r => r.json())
    .catch(err => {
      document.getElementById('result').textContent = 'Error: ' + err;
    });

  document.getElementById('result').textContent = JSON.stringify(response, null, 2);
});