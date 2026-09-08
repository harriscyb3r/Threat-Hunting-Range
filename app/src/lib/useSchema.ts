// Shared schema lookup for the editor: table names, all column names, and a
// column -> tables index for completion detail. Cached forever — the schema is
// static reference data.

import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'

interface SchemaData {
  tables: { name: string; columns: { name: string; type: string }[] }[]
  asim: { name: string }[]
}

export function useSchema() {
  const { data } = useQuery({
    queryKey: ['schema'],
    queryFn: async () => (await fetch('/api/range/schema')).json() as Promise<SchemaData>,
    staleTime: Infinity,
  })

  return useMemo(() => {
    const tables = new Set<string>()
    const columns = new Set<string>()
    const columnTables = new Map<string, string[]>()
    if (data) {
      for (const t of data.tables) {
        tables.add(t.name)
        for (const c of t.columns) {
          columns.add(c.name)
          const list = columnTables.get(c.name) ?? []
          list.push(t.name)
          columnTables.set(c.name, list)
        }
      }
      for (const p of data.asim) tables.add(p.name)
    }
    return { tables, columns, columnTables, loaded: !!data }
  }, [data])
}
