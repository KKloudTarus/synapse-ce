const field = (name: string, label: string, kind = 'text', required = true, description = '') => ({ name, label, kind, required, description })
export const providers = [
  { provider: 'jenkins', name: 'Jenkins', description: 'Read-only pipeline discovery and build correlation.', capabilities: ['test_connection', 'discover_pipelines', 'read_runs'], config_fields: [], secret_fields: [field('username', 'Username'), field('api_token', 'API token', 'password')] },
  { provider: 'azure-pipelines', name: 'Azure Pipelines', description: 'Read-only pipeline discovery and build correlation.', capabilities: ['test_connection', 'discover_pipelines', 'read_runs'], config_fields: [], secret_fields: [field('pat', 'Read-only personal access token', 'password')] },
  ...['github', 'gitlab', 'bitbucket'].map((provider, i) => ({ provider, name: ['GitHub', 'GitLab', 'Bitbucket Cloud'][i], description: 'Inbound repository events bound to one Git-backed Project.', capabilities: [], config_fields: [], secret_fields: [] })),
]
