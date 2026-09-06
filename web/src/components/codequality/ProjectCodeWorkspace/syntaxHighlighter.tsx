import type { ProjectCodeFinding } from '../../../lib/types'

type TokenType =
  | 'comment'
  | 'string'
  | 'keyword'
  | 'type'
  | 'key'
  | 'number'
  | 'function'
  | 'operator'
  | 'punctuation'
  | 'text'

interface Token {
  type: TokenType
  text: string
}

const GO_KEYWORDS = new Set([
  'break', 'case', 'chan', 'const', 'continue', 'default', 'defer', 'else',
  'fallthrough', 'for', 'func', 'go', 'goto', 'if', 'import', 'interface',
  'map', 'package', 'range', 'return', 'select', 'struct', 'switch', 'type',
  'var', 'iota',
])

const GO_TYPES = new Set([
  'bool', 'byte', 'complex64', 'complex128', 'error', 'float32', 'float64',
  'int', 'int8', 'int16', 'int32', 'int64', 'rune', 'string', 'uint',
  'uint8', 'uint16', 'uint32', 'uint64', 'uintptr', 'any',
])

const JS_KEYWORDS = new Set([
  'async', 'await', 'break', 'case', 'catch', 'class', 'const', 'continue',
  'debugger', 'default', 'delete', 'do', 'else', 'export', 'extends', 'finally',
  'for', 'from', 'function', 'if', 'import', 'in', 'instanceof', 'let', 'new',
  'return', 'super', 'switch', 'this', 'throw', 'try', 'typeof', 'var', 'void',
  'while', 'with', 'yield', 'type', 'interface', 'as', 'enum',
])

const PYTHON_KEYWORDS = new Set([
  'and', 'as', 'assert', 'async', 'await', 'break', 'class', 'continue', 'def',
  'del', 'elif', 'else', 'except', 'finally', 'for', 'from', 'global', 'if',
  'import', 'in', 'is', 'lambda', 'nonlocal', 'not', 'or', 'pass', 'raise',
  'return', 'try', 'while', 'with', 'yield', 'self',
])

const MAKEFILE_KEYWORDS = new Set([
  'include', 'ifeq', 'ifneq', 'ifdef', 'ifndef', 'else', 'endif', 'define', 'endef',
  'export', 'unexport', 'override',
])

function detectLang(filename: string): 'go' | 'js' | 'python' | 'yaml' | 'json' | 'makefile' | 'shell' | 'docker' | 'generic' {
  const name = filename.toLowerCase()
  if (name.endsWith('.go')) return 'go'
  if (name.endsWith('.ts') || name.endsWith('.tsx') || name.endsWith('.js') || name.endsWith('.jsx') || name.endsWith('.mjs')) return 'js'
  if (name.endsWith('.py')) return 'python'
  if (name.endsWith('.yaml') || name.endsWith('.yml')) return 'yaml'
  if (name.endsWith('.json')) return 'json'
  if (name.includes('makefile') || name.endsWith('.mk')) return 'makefile'
  if (name.endsWith('.sh') || name.endsWith('.bash') || name.endsWith('.zsh')) return 'shell'
  if (name.includes('dockerfile')) return 'docker'
  return 'generic'
}

export function tokenizeLine(line: string, filename: string): Token[] {
  const lang = detectLang(filename)
  const tokens: Token[] = []
  let i = 0
  const len = line.length

  while (i < len) {
    // 1. Comments
    if (
      ((lang === 'go' || lang === 'js') && line.slice(i, i + 2) === '//') ||
      ((lang === 'yaml' || lang === 'python' || lang === 'makefile' || lang === 'shell' || lang === 'docker') && line[i] === '#')
    ) {
      tokens.push({ type: 'comment', text: line.slice(i) })
      break
    }

    // 2. YAML / JSON Keys
    if (lang === 'yaml') {
      const keyMatch = /^([A-Za-z0-9_-]+):(\s*)/.exec(line.slice(i))
      if (keyMatch) {
        tokens.push({ type: 'key', text: keyMatch[1] })
        tokens.push({ type: 'punctuation', text: ':' })
        if (keyMatch[2]) tokens.push({ type: 'text', text: keyMatch[2] })
        i += keyMatch[0].length
        continue
      }
    }

    if (lang === 'json') {
      const jsonKeyMatch = /^"([^"]+)"(\s*:)/.exec(line.slice(i))
      if (jsonKeyMatch) {
        tokens.push({ type: 'key', text: `"${jsonKeyMatch[1]}"` })
        tokens.push({ type: 'punctuation', text: jsonKeyMatch[2] })
        i += jsonKeyMatch[0].length
        continue
      }
    }

    // 3. Strings
    const char = line[i]
    if (char === '"' || char === "'" || char === '`') {
      const quote = char
      let j = i + 1
      while (j < len) {
        if (line[j] === '\\' && j + 1 < len) {
          j += 2
          continue
        }
        if (line[j] === quote) {
          j++
          break
        }
        j++
      }
      tokens.push({ type: 'string', text: line.slice(i, j) })
      i = j
      continue
    }

    // 4. Numbers & Booleans
    const numMatch = /^(0x[0-9a-fA-F]+|\d+(\.\d+)?)/.exec(line.slice(i))
    if (numMatch && (i === 0 || /[^A-Za-z0-9_]/.test(line[i - 1]))) {
      tokens.push({ type: 'number', text: numMatch[0] })
      i += numMatch[0].length
      continue
    }

    // 5. Identifiers, Keywords, Types, Function calls
    const identMatch = /^[A-Za-z_][A-Za-z0-9_]*/.exec(line.slice(i))
    if (identMatch) {
      const word = identMatch[0]
      const nextChar = line[i + word.length]

      if (word === 'true' || word === 'false' || word === 'nil' || word === 'null' || word === 'None' || word === 'True' || word === 'False') {
        tokens.push({ type: 'number', text: word })
      } else if (
        (lang === 'go' && GO_KEYWORDS.has(word)) ||
        (lang === 'js' && JS_KEYWORDS.has(word)) ||
        (lang === 'python' && PYTHON_KEYWORDS.has(word)) ||
        (lang === 'makefile' && MAKEFILE_KEYWORDS.has(word))
      ) {
        tokens.push({ type: 'keyword', text: word })
      } else if (lang === 'go' && GO_TYPES.has(word)) {
        tokens.push({ type: 'type', text: word })
      } else if (nextChar === '(') {
        tokens.push({ type: 'function', text: word })
      } else {
        tokens.push({ type: 'text', text: word })
      }

      i += word.length
      continue
    }

    // 6. Operators & Punctuation
    const opMatch = /^(:=|[=+\-*/%&|^!<>]=?|&&|\|\||\?|:)/.exec(line.slice(i))
    if (opMatch) {
      tokens.push({ type: 'operator', text: opMatch[0] })
      i += opMatch[0].length
      continue
    }

    if (/^[{}()[\];,.]/.test(char)) {
      tokens.push({ type: 'punctuation', text: char })
      i++
      continue
    }

    // 7. Plain text / whitespace
    tokens.push({ type: 'text', text: char })
    i++
  }

  return tokens
}

function tokenClass(type: TokenType): string {
  switch (type) {
    case 'keyword':
      return 'text-utility-purple-600 font-semibold'
    case 'key':
      return 'text-utility-indigo-600 font-semibold'
    case 'string':
      return 'text-utility-green-600'
    case 'number':
      return 'text-utility-orange-600 font-mono'
    case 'function':
      return 'text-utility-sky-600 font-medium'
    case 'type':
      return 'text-utility-amber-600'
    case 'comment':
      return 'text-tertiary italic select-none'
    case 'operator':
      return 'text-utility-pink-600'
    case 'punctuation':
      return 'text-secondary'
    case 'text':
    default:
      return 'text-primary'
  }
}

export function HighlightedCodeLine({
  content,
  filename,
  finding,
  line,
}: {
  content: string
  filename: string
  finding: ProjectCodeFinding | null
  line: number
}) {
  const isFindingLine = finding && line >= finding.location.startLine && line <= finding.location.endLine

  if (!isFindingLine) {
    const tokens = tokenizeLine(content, filename)
    return (
      <>
        {tokens.map((tok, idx) => (
          <span key={idx} className={tokenClass(tok.type)}>
            {tok.text}
          </span>
        ))}
      </>
    )
  }

  // Finding highlight on this line
  const start = line === finding.location.startLine ? finding.location.startColumn : null
  const end = line === finding.location.endLine ? finding.location.endColumn : null

  if (start === null && end === null) {
    const tokens = tokenizeLine(content, filename)
    return (
      <mark className="bg-error-primary/20 text-inherit rounded-xs px-0.5 border-b border-error-primary/40">
        {tokens.map((tok, idx) => (
          <span key={idx} className={tokenClass(tok.type)}>
            {tok.text}
          </span>
        ))}
      </mark>
    )
  }

  const from = Math.max(0, start ?? 0)
  const to = Math.max(from, Math.min(content.length, end ?? content.length))

  const beforeText = content.slice(0, from)
  const matchText = content.slice(from, to)
  const afterText = content.slice(to)

  const beforeTokens = tokenizeLine(beforeText, filename)
  const matchTokens = tokenizeLine(matchText, filename)
  const afterTokens = tokenizeLine(afterText, filename)

  return (
    <>
      {beforeTokens.map((tok, idx) => (
        <span key={`b-${idx}`} className={tokenClass(tok.type)}>
          {tok.text}
        </span>
      ))}
      <mark className="bg-error-primary/25 text-inherit rounded-xs px-0.5 border-b-2 border-error-primary">
        {matchTokens.map((tok, idx) => (
          <span key={`m-${idx}`} className={tokenClass(tok.type)}>
            {tok.text}
          </span>
        ))}
      </mark>
      {afterTokens.map((tok, idx) => (
        <span key={`a-${idx}`} className={tokenClass(tok.type)}>
          {tok.text}
        </span>
      ))}
    </>
  )
}
