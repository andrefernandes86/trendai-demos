/* TrendAI Solutions Demo Center — content model.
 *
 * Industries (fictional companies), the official Trend Vision One solution
 * modules, and the demo stories that tie tools together. The Demo Center pages
 * (center/industry/story) render entirely from this file; tools come from
 * demos.js. Keep product names as the official Vision One module names.
 */
(function () {
  // Official Trend Vision One modules shown in the Demo Center.
  const SOLUTIONS = [
    { id: 'ai', name: 'AI Security', blurb: 'AI Guard, AI Scanner (TMAS) and ZTSA AI Service Access.', color: '#22d3ee' },
    { id: 'file', name: 'File Security', blurb: 'File Security SDK for uploads and cloud file storage.', color: '#38bdf8' },
    { id: 'network', name: 'Network Security', blurb: 'Network Detection & Response and TippingPoint IPS.', color: '#818cf8' },
    { id: 'cloud', name: 'Cloud Security', blurb: 'Cloud Posture and Container Security.', color: '#2dd4bf' },
    { id: 'workload', name: 'Server & Workload Protection', blurb: 'Anti-Malware, IPS, Integrity Monitoring, Log Inspection.', color: '#fb923c' },
    { id: 'endpoint', name: 'Endpoint Security', blurb: 'Endpoint Sensor and behaviour monitoring.', color: '#f472b6' },
    { id: 'asrm', name: 'Attack Surface Risk Management', blurb: 'Cyber Risk Exposure Management (CREM).', color: '#a3e635' },
    { id: 'xdr', name: 'XDR & Agentic SIEM', blurb: 'Workbench, Threat Intelligence and Agentic SIEM.', color: '#c084fc' },
  ];

  // Steps reference a tool by its demos.js id (opens /tool/<id>), or an action
  // the Demo Center runs itself. `expect` = what the viewer should see;
  // `solution` = the Vision One module; `console` = where it shows in Vision One.
  const INDUSTRIES = [
    {
      id: 'finance', name: 'Financial services', company: 'Northbridge Bank', assistant: 'Nora', color: '#38bdf8', icon: 'bank',
      tagline: 'Retail bank with an AI banking assistant, branch file shares and a payments API.',
      regs: ['PCI DSS', 'DORA', 'GLBA'],
      risks: ['AI copilot abuse and data leaks', 'Ransomware on branch file shares', 'Payments API attacks', 'Customer smishing'],
      tenant: 'finance',
      stories: [
        {
          id: 'fin-ai-copilot', title: 'The AI assistant leaks another customer’s account', minutes: 8, solution: 'ai', featured: true,
          summary: 'Trick Nora into revealing someone else’s balance and wiring money, then switch on AI Guard and watch the same attacks fail.',
          steps: [
            { title: 'Meet Nora, the banking assistant', tool: 'ai-target', expect: 'A normal balance-and-transactions chat for the signed-in customer.', solution: 'ai' },
            { title: 'Leak another customer’s account', tool: 'ai-target', expect: 'Nora returns a different customer’s balance, SSN and a large wire — a broken-object-level-authorization flaw.', solution: 'ai', console: 'n/a (baseline, unprotected)' },
            { title: 'Attach a receipt with a hidden instruction', tool: 'ai-target', expect: 'A Word receipt carries invisible text telling Nora to wire money. File Security finds no malware; the text reaches the model.', solution: 'file' },
            { title: 'Turn on TrendAI protection', action: 'enable-protection', expect: 'AI Guard now screens prompts, responses, context and document text; File Security scans every file.', solution: 'ai', console: 'AI Security → AI Guard activity' },
            { title: 'Re-run the attacks', tool: 'ai-target', expect: 'The injection, the cross-customer lookup and the poisoned document are all blocked. Compare with the answer key.', solution: 'ai', console: 'AI Security → AI Guard activity' },
          ],
        },
        {
          id: 'fin-ransomware', title: 'Ransomware lands on a branch file share', minutes: 6, solution: 'file',
          summary: 'Drop malware into the bank’s shared drive and watch the File Security SDK catch it before it spreads.',
          steps: [
            { title: 'Scan the branch share', tool: 'v1fs', expect: 'A clean on-demand scan of the mounted share.', solution: 'file' },
            { title: 'Malware arrives', tool: 'v1fs', expect: 'An EICAR sample is flagged; the detection shows in Vision One.', solution: 'file', console: 'File Security → detections' },
          ],
        },
        {
          id: 'fin-api', title: 'Attacker hits the payments API', minutes: 7, solution: 'cloud',
          summary: 'Run SQL-injection and auth-bypass attacks against the bank’s API.',
          steps: [
            { title: 'Explore the payments API', tool: 'vuln-api', expect: 'A deliberately vulnerable API with login, posts and CRUD.', solution: 'cloud' },
            { title: 'SQL injection and auth bypass', tool: 'vuln-api', expect: 'Injection dumps accounts; weak auth is bypassed — the kind of flaw Cloud/Container Security and a WAF catch.', solution: 'cloud', console: 'Cloud Security → findings' },
          ],
        },
        {
          id: 'fin-smish', title: 'Customers get a smishing text', minutes: 5, solution: 'network',
          summary: 'Show what a malicious bank SMS link silently collects — awareness only.',
          steps: [
            { title: 'Open the smishing lure', tool: 'smish', expect: 'A fake Northbridge alert link and what it harvests from a device.', solution: 'network' },
          ],
        },
        {
          id: 'fin-sizing', title: 'Size Agentic SIEM for the bank', minutes: 5, solution: 'xdr',
          summary: 'Walk the sizing wizard for a bank’s log, endpoint and cloud volumes.',
          steps: [
            { title: 'Run the sizing wizard', tool: 'siemcalc', expect: 'Credit sizing across ingestion, endpoint/cloud and CREM, with a PDF.', solution: 'xdr' },
          ],
        },
      ],
    },
    {
      id: 'healthcare', name: 'Healthcare', company: 'Meridian Health', assistant: 'Clara', color: '#2dd4bf', icon: 'heart',
      tagline: 'Hospital network with a patient-portal assistant, imaging archives and connected devices.',
      regs: ['HIPAA', 'HITECH'],
      risks: ['Patient data leaks from the portal assistant', 'Poisoned lab reports', 'Ransomware on imaging archives', 'Medical-device network traffic'],
      tenant: 'healthcare',
      stories: [
        {
          id: 'hc-poisoned-doc', title: 'A poisoned lab report reaches the patient assistant', minutes: 6, solution: 'file', featured: true,
          summary: 'Upload an outside lab report carrying invisible instructions. File Security checks it for malware; AI Guard finds the hidden text.',
          steps: [
            { title: 'Meet Clara, the patient assistant', tool: 'ai-target', expect: 'A normal appointments-and-results chat for the signed-in patient.', solution: 'ai' },
            { title: 'Upload the outside lab report', tool: 'ai-target', expect: 'A Word report hides white 1-pt text telling Clara to read out another patient’s HIV results.', solution: 'file' },
            { title: 'Turn on TrendAI protection', action: 'enable-protection', expect: 'File Security scans the file; AI Guard scans the extracted text in 50 KB chunks.', solution: 'ai', console: 'AI Security → AI Guard activity' },
            { title: 'Re-run the upload', tool: 'ai-target', expect: 'The hidden instruction is blocked and the cross-patient leak never happens.', solution: 'ai', console: 'AI Security → AI Guard activity' },
          ],
        },
        {
          id: 'hc-redteam', title: 'Red-team the patient assistant with AI Scanner', minutes: 8, solution: 'ai',
          summary: 'Run the real tmas aiscan battery against the model behind Clara.',
          steps: [
            { title: 'Scan the model', tool: 'ai-scanner', expect: 'Adversarial probes mapped to the OWASP Top 10 for LLM Applications.', solution: 'ai', console: 'AI Security → AI Scanner' },
          ],
        },
        {
          id: 'hc-devices', title: 'Medical-device traffic on the network', minutes: 7, solution: 'network',
          summary: 'Replay device and attack traffic so a network sensor on the segment detects it.',
          steps: [
            { title: 'Replay the traffic', tool: 'net-replay', expect: 'Benign device traffic alongside exploits and C2; your NDR/IPS sensor flags the malicious flows.', solution: 'network', console: 'Network Security → detections' },
          ],
        },
        {
          id: 'hc-imaging', title: 'Ransomware on the imaging archive', minutes: 6, solution: 'file',
          summary: 'Scan the imaging share and catch malware with the File Security SDK.',
          steps: [
            { title: 'Scan the archive', tool: 'v1fs', expect: 'A clean scan, then an EICAR detection.', solution: 'file', console: 'File Security → detections' },
          ],
        },
      ],
    },
    {
      id: 'manufacturing', name: 'Manufacturing & OT', company: 'Halden Manufacturing', assistant: 'Otto', color: '#fb923c', icon: 'factory',
      tagline: 'Plant with an internet-facing MES portal, a SCADA network and containerised edge apps.',
      regs: ['IEC 62443', 'NIS2'],
      risks: ['Exploit of the internet-facing plant server', 'Lateral movement toward OT', 'OT protocol attacks', 'Container drift at the edge'],
      tenant: 'finance',
      stories: [
        {
          id: 'mfg-struts', title: 'An attacker exploits the plant’s MES portal', minutes: 10, solution: 'workload', featured: true,
          summary: 'Run a real Apache Struts exploit against the plant server, then replay OT attacks across the network sensor.',
          steps: [
            { title: 'The exposed MES portal', tool: 'struts-target', expect: 'An Apache Struts web app reachable on the plant network.', solution: 'workload' },
            { title: 'Exploit it', tool: 'struts-target', expect: 'A remote-code-execution exploit lands — Server & Workload Protection IPS (virtual patching) blocks it when an agent protects the host.', solution: 'workload', console: 'Server & Workload Protection → IPS events' },
            { title: 'Trigger the five protection modules', tool: 'workload-protection', expect: 'Anti-Malware, Web Reputation, IPS, Integrity Monitoring and Log Inspection each catch a stage, with real host activity.', solution: 'workload', console: 'Server & Workload Protection → events' },
            { title: 'Move toward OT', tool: 'net-replay', expect: 'Replay OT/ICS protocol attacks; your network sensor on the OT segment detects them.', solution: 'network', console: 'Network Security → detections' },
          ],
        },
        {
          id: 'mfg-container', title: 'Container drift on the edge cluster', minutes: 8, solution: 'cloud',
          summary: 'Deploy a vulnerable workload and let Container Security catch it (external lab).',
          steps: [
            { title: 'Connect the lab cluster', action: 'lab-k8s', expect: 'Point at your Kubernetes lab in Settings (cluster URL + token).', solution: 'cloud' },
            { title: 'Deploy a vulnerable workload', tool: 'vuln-api', expect: 'Container Security admission control and runtime rules flag it.', solution: 'cloud', console: 'Cloud Security → Container Security' },
          ],
        },
        {
          id: 'mfg-network', title: 'OT protocol attacks on the wire', minutes: 7, solution: 'network',
          summary: 'Replay a spread of ICS/OT attack traffic for a network sensor.',
          steps: [
            { title: 'Replay OT traffic', tool: 'net-replay', expect: 'ICS protocol exploits and scans; the sensor detects them.', solution: 'network', console: 'Network Security → detections' },
          ],
        },
        {
          id: 'mfg-risk', title: 'See the plant’s exposure in CREM', minutes: 5, solution: 'asrm',
          summary: 'Query attack-surface risk through the Vision One MCP server.',
          steps: [
            { title: 'Ask about exposure', tool: 'v1-chatbot', expect: 'Natural-language queries to Attack Surface Risk Management (CREM) and Workbench.', solution: 'asrm', console: 'Attack Surface Risk Management' },
          ],
        },
      ],
    },
    {
      id: 'retail', name: 'Retail & e-commerce', company: 'Lumen Market', assistant: 'Lumi', color: '#c084fc', icon: 'cart',
      tagline: 'Online and in-store retailer with a shopping assistant, a checkout API and a loyalty app.',
      regs: ['PCI DSS', 'GDPR'],
      risks: ['Checkout and loyalty API attacks', 'Shopping-assistant jailbreaks', 'Shopper smishing', 'Card data exposure'],
      tenant: 'finance',
      stories: [
        {
          id: 'ret-assistant', title: 'Jailbreak the shopping assistant', minutes: 7, solution: 'ai', featured: true,
          summary: 'Push the store assistant off-topic and into unsafe output, then block it with AI Guard.',
          steps: [
            { title: 'Meet Lumi, the shopping assistant', tool: 'ai-target', expect: 'A normal product-and-order chat.', solution: 'ai' },
            { title: 'Jailbreak and unsafe output', tool: 'ai-target', expect: 'Persona override and HTML/script in a reply — improper output handling.', solution: 'ai' },
            { title: 'Turn on TrendAI protection', action: 'enable-protection', expect: 'AI Guard blocks the jailbreak and sanitises output.', solution: 'ai', console: 'AI Security → AI Guard activity' },
          ],
        },
        {
          id: 'ret-api', title: 'Attack the checkout API', minutes: 7, solution: 'cloud',
          summary: 'SQLi and auth bypass against the retail API.',
          steps: [
            { title: 'Explore the checkout API', tool: 'vuln-api', expect: 'A vulnerable API with the usual flaws.', solution: 'cloud' },
            { title: 'Exploit it', tool: 'vuln-api', expect: 'Injection and auth bypass dump orders and accounts.', solution: 'cloud', console: 'Cloud Security → findings' },
          ],
        },
        {
          id: 'ret-smish', title: 'Shoppers get a fake delivery text', minutes: 5, solution: 'network',
          summary: 'A smishing lure branded as a delivery notice — awareness only.',
          steps: [
            { title: 'Open the lure', tool: 'smish', expect: 'What a tapped link harvests from a device.', solution: 'network' },
          ],
        },
        {
          id: 'ret-files', title: 'Malware in a supplier upload', minutes: 5, solution: 'file',
          summary: 'Scan supplier files with the File Security SDK.',
          steps: [
            { title: 'Scan an upload', tool: 'app-sec', expect: 'A clean file, then an EICAR detection, inside an AI chatbot upload.', solution: 'file', console: 'File Security → detections' },
          ],
        },
      ],
    },
    {
      id: 'public', name: 'Public sector', company: 'Alder County Services', assistant: 'Ada', color: '#a3e635', icon: 'gov',
      tagline: 'County government with a citizen-services assistant, a records archive and staff using public AI tools.',
      regs: ['NIST 800-53', 'CJIS'],
      risks: ['Citizen data exposure from the assistant', 'Shadow AI use by staff', 'Phishing and smishing', 'Records-archive malware'],
      tenant: 'healthcare',
      stories: [
        {
          id: 'pub-assistant', title: 'The citizen assistant leaks records', minutes: 7, solution: 'ai', featured: true,
          summary: 'Extract another resident’s record from the county assistant, then block it with AI Guard.',
          steps: [
            { title: 'Meet Ada, the citizen assistant', tool: 'ai-target', expect: 'A normal services chat for the signed-in resident.', solution: 'ai' },
            { title: 'Extract another resident’s record', tool: 'ai-target', expect: 'A cross-record leak — broken object-level authorization.', solution: 'ai' },
            { title: 'Turn on TrendAI protection', action: 'enable-protection', expect: 'AI Guard blocks the extraction.', solution: 'ai', console: 'AI Security → AI Guard activity' },
          ],
        },
        {
          id: 'pub-shadow-ai', title: 'Staff paste records into public AI tools', minutes: 6, solution: 'ai',
          summary: 'Show how ZTSA AI Service Access governs and inspects employee AI use.',
          steps: [
            { title: 'Check a risky prompt', action: 'prompt-check', expect: 'A prompt with citizen PII is flagged — the kind of control ZTSA AI Service Access applies at the gateway.', solution: 'ai', console: 'AI Security → ZTSA AI Service Access' },
          ],
        },
        {
          id: 'pub-phishing', title: 'A phishing campaign hits county staff', minutes: 5, solution: 'network',
          summary: 'A smishing lure and what it harvests — awareness only.',
          steps: [
            { title: 'Open the lure', tool: 'smish', expect: 'What a tapped link collects.', solution: 'network' },
          ],
        },
        {
          id: 'pub-records', title: 'Malware in the records archive', minutes: 5, solution: 'file',
          summary: 'Scan the archive with the File Security SDK.',
          steps: [
            { title: 'Scan the archive', tool: 'v1fs', expect: 'A clean scan, then an EICAR detection.', solution: 'file', console: 'File Security → detections' },
          ],
        },
      ],
    },
  ];

  // Quick self-service checks on the home page.
  const QUICK = [
    { id: 'prompt-check', name: 'Prompt check', solution: 'ai', tool: 'ai-target', blurb: 'Type something you’d send to an AI assistant; AI Guard says if it’s an attack.' },
    { id: 'doc-check', name: 'Document check', solution: 'file', tool: 'ai-target', blurb: 'Upload a PDF, Word or text file; File Security scans for malware and AI Guard scans the text.' },
    { id: 'assistants', name: 'Industry AI assistants', solution: 'ai', tool: 'ai-target', blurb: 'Chat with each company’s assistant and switch TrendAI protection on and off.' },
  ];

  window.TRENDAI_CENTER = { SOLUTIONS, INDUSTRIES, QUICK };
})();
