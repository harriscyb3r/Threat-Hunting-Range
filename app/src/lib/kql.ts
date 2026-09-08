// Minimal KQL language support for the Query Lab.
//
// Not a full parser — a tokenizer good enough for syntax highlighting and
// schema-aware completion. This is a deliberate choice over @kusto/monaco-kusto,
// which ships as an AMD bundle that fights Vite's ESM build and drags in a large
// language service the range does not need. A hand-rolled tokenizer over our own
// table registry is ~200 lines and does exactly what a hunter needs: colour the
// query and suggest the next column.

export const KQL_OPERATORS = [
  'where', 'project', 'project-away', 'project-rename', 'extend', 'summarize',
  'order', 'sort', 'top', 'top-nested', 'take', 'limit', 'distinct', 'count',
  'join', 'union', 'let', 'mv-expand', 'mv-apply', 'evaluate', 'parse',
  'parse-where', 'make-series', 'range', 'render', 'lookup', 'sample',
  'sample-distinct', 'getschema', 'search', 'find', 'invoke', 'scan', 'partition',
  'serialize', 'as', 'consume', 'facet', 'fork',
]

export const KQL_KEYWORDS = [
  'by', 'on', 'asc', 'desc', 'and', 'or', 'not', 'in', 'has', 'has_any',
  'has_all', 'contains', 'startswith', 'endswith', 'matches', 'regex', 'between',
  'kind', 'step', 'from', 'to', 'nulls', 'first', 'last', 'hint', 'materialize',
  'true', 'false', 'null', 'typeof', 'toscalar', 'datatable', 'print',
  'inner', 'leftouter', 'rightouter', 'fullouter', 'leftanti', 'rightanti',
  'leftsemi', 'rightsemi', 'anti', 'semi', 'isfuzzy',
]

export const KQL_FUNCTIONS = [
  'count', 'countif', 'dcount', 'dcountif', 'sum', 'sumif', 'avg', 'avgif',
  'min', 'max', 'make_set', 'make_list', 'make_bag', 'arg_max', 'arg_min',
  'percentile', 'percentiles', 'stdev', 'variance', 'any', 'anyif', 'take_any',
  'bin', 'floor', 'ceiling', 'round', 'abs', 'sign', 'exp', 'log', 'pow', 'sqrt',
  'ago', 'now', 'datetime', 'timespan', 'startofday', 'endofday', 'startofweek',
  'startofmonth', 'dayofweek', 'dayofmonth', 'dayofyear', 'hourofday',
  'getmonth', 'getyear', 'weekofyear', 'monthofyear', 'datetime_add',
  'datetime_diff', 'datetime_part', 'format_datetime', 'format_timespan',
  'make_datetime', 'unixtime_seconds_todatetime',
  'strlen', 'strcat', 'strcat_delim', 'substring', 'split', 'strrep', 'trim',
  'trim_start', 'trim_end', 'replace_string', 'replace_regex', 'reverse',
  'toupper', 'tolower', 'indexof', 'countof', 'extract', 'extract_all',
  'extractjson', 'parse_json', 'todynamic', 'parse_url', 'parse_urlquery',
  'parse_path', 'parse_ipv4', 'parse_version', 'bag_keys', 'bag_merge',
  'bag_unpack', 'pack', 'pack_array', 'zip', 'array_length', 'array_slice',
  'array_concat', 'array_index_of', 'array_sort_asc', 'array_sort_desc',
  'set_has_element', 'set_union', 'set_intersect', 'set_difference',
  'tostring', 'toint', 'tolong', 'toreal', 'todouble', 'tobool', 'todatetime',
  'totimespan', 'toguid', 'tohex', 'iff', 'iif', 'case', 'coalesce', 'isnull',
  'isnotnull', 'isempty', 'isnotempty', 'isnan', 'isfinite', 'hash', 'hash_sha256',
  'hash_md5', 'hash_sha1', 'base64_encode_tostring', 'base64_decode_tostring',
  'ipv4_is_private', 'ipv4_is_in_range', 'ipv4_is_in_any_range', 'ipv4_compare',
  'ipv4_netmask_suffix', 'geo_info_from_ip_address', 'gethostname',
  'series_decompose', 'series_decompose_anomalies', 'series_fit_line',
  'series_fit_2lines', 'series_outliers', 'series_periods_detect', 'prev', 'next',
  'row_number', 'row_cumsum', 'row_window_session', 'rand',
]

export const KQL_PLUGINS = [
  'autocluster', 'basket', 'diffpatterns', 'pivot', 'bag_unpack',
  'narrow', 'sql_request', 'dcount_intersect',
]

type TokenKind =
  | 'operator' | 'keyword' | 'function' | 'table' | 'column' | 'string'
  | 'number' | 'comment' | 'pipe' | 'punct' | 'ident' | 'ws'

export interface Token {
  text: string
  kind: TokenKind
}

const OP_SET = new Set(KQL_OPERATORS)
const KW_SET = new Set(KQL_KEYWORDS)
const FN_SET = new Set(KQL_FUNCTIONS.concat(KQL_PLUGINS))

// Tokenize a line for highlighting. Tables/columns are resolved by the caller
// against the schema registry (passed as sets), since they are data-driven.
export function tokenizeLine(
  line: string,
  tables: Set<string>,
  columns: Set<string>,
): Token[] {
  const tokens: Token[] = []
  let i = 0
  const n = line.length

  while (i < n) {
    const c = line[i]

    // Comment to end of line.
    if (c === '/' && line[i + 1] === '/') {
      tokens.push({ text: line.slice(i), kind: 'comment' })
      break
    }
    // Whitespace.
    if (/\s/.test(c)) {
      let j = i
      while (j < n && /\s/.test(line[j])) j++
      tokens.push({ text: line.slice(i, j), kind: 'ws' })
      i = j
      continue
    }
    // Strings, single or double, with backslash escapes.
    if (c === '"' || c === "'") {
      let j = i + 1
      while (j < n && line[j] !== c) {
        if (line[j] === '\\') j++
        j++
      }
      tokens.push({ text: line.slice(i, Math.min(j + 1, n)), kind: 'string' })
      i = j + 1
      continue
    }
    // Numbers (incl. hex and decimals).
    if (/[0-9]/.test(c) || (c === '.' && /[0-9]/.test(line[i + 1] ?? ''))) {
      let j = i
      while (j < n && /[0-9a-fx.]/i.test(line[j])) j++
      tokens.push({ text: line.slice(i, j), kind: 'number' })
      i = j
      continue
    }
    // Pipe.
    if (c === '|') {
      tokens.push({ text: c, kind: 'pipe' })
      i++
      continue
    }
    // Identifiers (may include _ and -, since KQL operators use hyphens).
    if (/[A-Za-z_]/.test(c)) {
      let j = i
      while (j < n && /[A-Za-z0-9_]/.test(line[j])) j++
      // Allow a single hyphen inside operator names like project-away.
      if (line[j] === '-' && /[A-Za-z]/.test(line[j + 1] ?? '')) {
        let k = j + 1
        while (k < n && /[A-Za-z0-9_]/.test(line[k])) k++
        const withHyphen = line.slice(i, k)
        if (OP_SET.has(withHyphen)) {
          tokens.push({ text: withHyphen, kind: 'operator' })
          i = k
          continue
        }
      }
      const word = line.slice(i, j)
      const lower = word.toLowerCase()
      let kind: TokenKind = 'ident'
      if (OP_SET.has(lower)) kind = 'operator'
      else if (KW_SET.has(lower)) kind = 'keyword'
      else if (FN_SET.has(lower)) kind = 'function'
      else if (tables.has(word)) kind = 'table'
      else if (columns.has(word)) kind = 'column'
      tokens.push({ text: word, kind })
      i = j
      continue
    }
    // Punctuation / operators.
    tokens.push({ text: c, kind: 'punct' })
    i++
  }
  return tokens
}

export const TOKEN_CLASS: Record<TokenKind, string> = {
  operator: 'text-accent-light font-medium',
  keyword: 'text-sky-400',
  function: 'text-violet-400',
  table: 'text-amber-300',
  column: 'text-emerald-300',
  string: 'text-orange-300',
  number: 'text-rose-300',
  comment: 'text-txt-3 italic',
  pipe: 'text-txt-2',
  punct: 'text-txt-2',
  ident: 'text-txt',
  ws: '',
}
