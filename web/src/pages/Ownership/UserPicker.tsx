import { useEffect, useId, useRef, useState } from 'react'
import { api } from '../../lib/api'
import type { UserChoice } from '../../lib/api/ownership'

export function UserPicker({team,value,onChange,disabled=false,allowAll=false}:{team:string;value:string;onChange:(id:string)=>void;disabled?:boolean;allowAll?:boolean}) {
  const [query,setQuery]=useState('')
  const [items,setItems]=useState<UserChoice[]>([])
  const [next,setNext]=useState<string>()
  const [selected,setSelected]=useState<UserChoice|null>(null)
  const [loading,setLoading]=useState(false)
  const [error,setError]=useState('')
  const generation=useRef(0)
  const searchID=useId()
  useEffect(()=>{
    const current=++generation.current
    const controller=new AbortController()
    setLoading(true);setError('');setItems([]);setNext(undefined)
    if(!team&&!allowAll){setLoading(false);return ()=>controller.abort()}
    const timer=setTimeout(()=>{
      void api.userChoices(team,query,undefined,controller.signal).then(page=>{
        if(current!==generation.current)return
        setItems(page.items);setNext(page.next)
      }).catch(err=>{
        if(current===generation.current && !controller.signal.aborted)setError(err instanceof Error?err.message:'Could not search users')
      }).finally(()=>{if(current===generation.current)setLoading(false)})
    },200)
    return ()=>{controller.abort();clearTimeout(timer)}
  },[team,query,allowAll])
  async function more(){
    if(!next||loading)return
    const current=generation.current
    setLoading(true);setError('')
    try{const page=await api.userChoices(team,query,next);if(current===generation.current){setItems(prev=>[...prev,...page.items]);setNext(page.next)}}
    catch(err){if(current===generation.current)setError(err instanceof Error?err.message:'Could not load more users')}
    finally{if(current===generation.current)setLoading(false)}
  }
  return <div className="space-y-2">
    <label htmlFor={searchID} className="text-sm font-medium text-primary">Assignee</label>
    {value&&<div className="flex items-center justify-between gap-2 rounded-lg border border-secondary p-2 text-sm text-secondary"><span className="truncate">Selected: {selected?.id===value?`${selected.name} (${value})`:value}</span><button type="button" disabled={disabled} onClick={()=>{setSelected(null);onChange('')}} className="text-primary underline">Clear</button></div>}
    <input id={searchID} type="search" value={query} disabled={disabled||(!team&&!allowAll)} onChange={e=>setQuery(e.target.value)} placeholder={team?'Search team members':allowAll?'Search users':'Choose a team first'} className="w-full rounded-lg border border-primary bg-primary px-3 py-2 text-primary disabled:opacity-50" />
    {error&&<p role="alert" className="text-sm text-error-primary">{error}</p>}
    {loading&&<p role="status" className="text-sm text-secondary">Searching users…</p>}
    {!loading&&!error&&items.length===0&&(team||allowAll)&&<p className="text-sm text-secondary">No eligible users found.</p>}
    {items.length>0&&<ul aria-label="Eligible team members" className="max-h-48 overflow-y-auto rounded-lg border border-secondary">{items.map(item=><li key={item.id}><button type="button" disabled={disabled} onClick={()=>{setSelected(item);onChange(item.id)}} className="w-full px-3 py-2 text-left text-sm text-primary hover:bg-primary_hover focus-visible:outline-2 focus-visible:outline-brand">{item.name} <span className="text-tertiary">({item.id})</span></button></li>)}</ul>}
    {next&&<button type="button" disabled={disabled||loading} onClick={()=>void more()} className="text-sm text-brand-primary underline disabled:opacity-50">Load more users</button>}
  </div>
}
