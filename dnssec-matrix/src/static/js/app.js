document.getElementById('queryForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const domain = document.getElementById('domain').value;
    const qtype = document.getElementById('qtype').value;
    const btnText = document.querySelector('button span');
    const loader = document.getElementById('loader');
    const terminal = document.getElementById('terminalOutput');
    
    // UI State Loading
    btnText.classList.add('hidden');
    loader.classList.remove('hidden');
    
    appendLine(`> Querying ${domain} IN ${qtype}...`, 'query');

    try {
        const response = await fetch('/api/query', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain, qtype })
        });
        
        const data = await response.json();
        
        if (data.status === "error") {
            appendLine(`[ERROR] ${data.message}`, 'error');
        } else {
            appendLine(`;; ->>HEADER<<- opcode: QUERY, status: ${data.status}`);
            appendLine(`;; QUESTION SECTION:`);
            appendLine(data.question);
            
            if (data.answer && data.answer.length > 0) {
                appendLine(`;; ANSWER SECTION:`, 'success');
                data.answer.forEach(ans => appendLine(ans, 'success'));
            }
            
            if (data.authority && data.authority.length > 0) {
                appendLine(`;; AUTHORITY SECTION:`, 'error');
                data.authority.forEach(auth => {
                    if (typeof auth === 'object') {
                        appendLine(auth.record);
                        appendLine(`;; DIAGNOSTIC NSEC3 HINT:`, 'highlight');
                        appendLine(`;; - Iterations: ${auth.iterations}`, 'highlight');
                        appendLine(`;; - Salt: ${auth.diagnostic_hint_salt}`, 'highlight');
                        appendLine(`;; - Algo: ${auth.hash_algo}`, 'highlight');
                    } else {
                        appendLine(auth);
                    }
                });
            }
            
            if (data.status === "NXDOMAIN" && (!data.authority || data.authority.length === 0)) {
                 appendLine(`;; No records found.`, 'comment');
            }
        }
    } catch (err) {
        appendLine(`[NETWORK ERROR] Failed to reach diagnostic server.`, 'error');
    } finally {
        // Restore UI State
        btnText.classList.remove('hidden');
        loader.classList.add('hidden');
        terminal.scrollTop = terminal.scrollHeight;
    }
});

function appendLine(text, className = '') {
    const terminal = document.getElementById('terminalOutput');
    const line = document.createElement('div');
    line.className = `line ${className}`;
    line.textContent = text;
    terminal.appendChild(line);
}
