// Mock AIDR telemetry: Teams -> AI Providers -> Models.
// Metrics mirror CrowdStrike AIDR Visibility: tokens, events, detections (+ detection-type breakdown).

const DETECTORS = [
  { key: 'prompt_injection', label: 'Prompt injection' },
  { key: 'pii',              label: 'Confidential & PII' },
  { key: 'secrets',          label: 'Secrets & keys' },
  { key: 'malicious',        label: 'Malicious entity' },
  { key: 'topic',            label: 'Topic violation' },
  { key: 'toxicity',         label: 'Toxicity' },
];

const PROVIDERS = {
  openai:      { label: 'OpenAI',        sanctioned: true,  risk: 1.0, models: [['gpt-5', 2400], ['gpt-4.1', 1900], ['gpt-4o', 1600], ['gpt-4o-mini', 900], ['o3', 3100], ['o4-mini', 1400]] },
  anthropic:   { label: 'Anthropic',     sanctioned: true,  risk: 0.8, models: [['claude-opus-4', 3600], ['claude-sonnet-4.5', 2800], ['claude-haiku-4.5', 1100]] },
  azureai:     { label: 'Azure OpenAI',  sanctioned: true,  risk: 0.7, models: [['gpt-4o', 1700], ['gpt-4.1', 2000], ['o3-mini', 1300]] },
  google:      { label: 'Google Gemini', sanctioned: true,  risk: 1.1, models: [['gemini-2.5-pro', 2600], ['gemini-2.5-flash', 1200], ['gemini-2.0-flash', 900]] },
  mistral:     { label: 'Mistral',       sanctioned: false, risk: 1.6, models: [['mistral-large', 1800], ['codestral', 2100], ['mistral-small', 800]] },
  deepseek:    { label: 'DeepSeek',      sanctioned: false, risk: 3.2, models: [['deepseek-r1', 3000], ['deepseek-v3', 1900]] },
  perplexity:  { label: 'Perplexity',    sanctioned: false, risk: 1.9, models: [['sonar-pro', 1500], ['sonar', 900]] },
  huggingface: { label: 'Hugging Face',  sanctioned: false, risk: 2.4, models: [['llama-3.1-70b', 1600], ['qwen2.5-72b', 1700], ['mixtral-8x22b', 1500]] },
  cohere:      { label: 'Cohere',        sanctioned: true,  risk: 0.9, models: [['command-r-plus', 1400], ['embed-v3', 300]] },
};

// [name, users, volume weight, risk factor, providers used, detector bias]
const TEAMS = [
  ['Engineering',      420, 10.0, 1.2, ['openai', 'anthropic', 'azureai', 'google', 'mistral', 'deepseek', 'huggingface'], { secrets: 5, prompt_injection: 2 }],
  ['Platform',         140,  5.5, 1.0, ['openai', 'anthropic', 'azureai', 'huggingface'],                                    { secrets: 4, malicious: 2 }],
  ['Data Science',     110,  6.5, 1.3, ['openai', 'anthropic', 'google', 'huggingface', 'mistral', 'cohere'],                { pii: 4, secrets: 2 }],
  ['ML Research',       60,  5.0, 1.5, ['openai', 'anthropic', 'google', 'deepseek', 'huggingface', 'mistral'],              { prompt_injection: 3, secrets: 2 }],
  ['Security',          45,  2.6, 0.7, ['openai', 'anthropic', 'azureai'],                                                    { malicious: 5, prompt_injection: 3 }],
  ['Product',           90,  3.1, 0.8, ['openai', 'anthropic', 'google', 'perplexity'],                                       { topic: 3, pii: 2 }],
  ['Design',            55,  1.4, 0.6, ['openai', 'anthropic', 'google'],                                                     { topic: 2, toxicity: 1 }],
  ['Marketing',         85,  3.4, 1.6, ['openai', 'anthropic', 'google', 'perplexity', 'deepseek'],                           { topic: 4, pii: 2, toxicity: 1 }],
  ['Sales',            160,  3.8, 1.7, ['openai', 'google', 'perplexity', 'deepseek'],                                        { pii: 5, topic: 2 }],
  ['Customer Success', 130,  4.2, 1.1, ['openai', 'anthropic', 'azureai', 'cohere'],                                          { pii: 6, toxicity: 2 }],
  ['Finance',           40,  1.6, 1.4, ['openai', 'azureai', 'deepseek'],                                                     { pii: 5, secrets: 2 }],
  ['Legal',             25,  1.0, 0.9, ['anthropic', 'azureai'],                                                              { pii: 6, topic: 1 }],
  ['People Ops',        35,  1.2, 1.2, ['openai', 'google', 'perplexity'],                                                    { pii: 7 }],
  ['IT Operations',     70,  2.4, 1.0, ['openai', 'anthropic', 'azureai', 'mistral'],                                         { secrets: 4, malicious: 2 }],
];

function mulberry32(seed) {
  return function () {
    seed |= 0; seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function splitDetections(total, bias, rand) {
  const weights = DETECTORS.map(d => (bias[d.key] || 0.4) * (0.5 + rand()));
  const sum = weights.reduce((a, b) => a + b, 0);
  const out = {};
  let left = total;
  DETECTORS.forEach((d, i) => {
    const n = i === DETECTORS.length - 1 ? left : Math.round((total * weights[i]) / sum);
    out[d.key] = Math.max(0, Math.min(n, left));
    left -= out[d.key];
  });
  return out;
}

function aggregate(node) {
  const kids = node.children;
  node.tokens = kids.reduce((s, c) => s + c.tokens, 0);
  node.events = kids.reduce((s, c) => s + c.events, 0);
  node.detections = kids.reduce((s, c) => s + c.detections, 0);
  node.byType = {};
  DETECTORS.forEach(d => { node.byType[d.key] = kids.reduce((s, c) => s + c.byType[d.key], 0); });
}

function buildData() {
  const rand = mulberry32(20261012);
  const teams = TEAMS.map(([name, users, weight, teamRisk, providerKeys, bias]) => {
    const team = { id: `team:${name}`, type: 'team', name, users, children: [] };

    team.children = providerKeys.map(pk => {
      const p = PROVIDERS[pk];
      const share = (p.sanctioned ? 1 : 0.35) * (0.4 + rand());
      const provider = {
        id: `${team.id}/provider:${pk}`, type: 'provider', key: pk, name: p.label,
        sanctioned: p.sanctioned, team: name, children: [],
      };

      const modelCount = Math.min(p.models.length, 2 + Math.floor(rand() * (p.models.length - 1)));
      provider.children = p.models.slice(0, modelCount).map(([model, avgTokens]) => {
        const events = Math.round(weight * share * 1800 * (0.25 + rand() * 1.2));
        const rate = 0.004 * teamRisk * p.risk * (0.4 + rand() * 1.6);
        const detections = Math.round(events * rate);
        return {
          id: `${provider.id}/model:${model}`, type: 'model', name: model,
          provider: p.label, sanctioned: p.sanctioned, team: name,
          events, tokens: Math.round(events * avgTokens * (0.7 + rand() * 0.6)), detections,
          users: Math.max(1, Math.round(users * share * (0.08 + rand() * 0.3))),
          byType: splitDetections(detections, bias, rand),
        };
      });

      aggregate(provider);
      provider.users = Math.min(users, Math.round(Math.max(...provider.children.map(m => m.users)) * 1.3));
      return provider;
    });

    aggregate(team);
    return team;
  });

  const root = { id: 'root', type: 'root', name: 'All teams', children: teams };
  aggregate(root);
  root.users = teams.reduce((s, t) => s + t.users, 0);
  return root;
}

const AIDR_DATA = buildData();
