import { req } from './client'
export type EnterpriseMember={id:string;personId:string;name:string;role:string;state:string;version:number}
export type EnterpriseInvitation={id:string;recipient:string;role:string;state:string;version:number;expiresAt:string}
const r=(v:unknown)=>v!==null&&typeof v==='object'?v as Record<string,unknown>:{}
const s=(v:unknown)=>typeof v==='string'?v:''
const n=(v:unknown)=>typeof v==='number'?v:0
const member=(v:unknown):EnterpriseMember=>{const x=r(v);return{id:s(x.id),personId:s(x.person_id),name:s(x.name),role:s(x.role),state:s(x.state),version:n(x.version)}}
const invite=(v:unknown):EnterpriseInvitation=>{const x=r(v);return{id:s(x.id),recipient:s(x.recipient),role:s(x.role),state:s(x.state),version:n(x.version),expiresAt:s(x.expires_at)}}
export const identityAdministration={
  async bootstrap(){const x=r(await req('/identity/bootstrap',{method:'POST'}));const proof=s(x.bootstrap_eligibility);if(!proof)throw new Error('The server did not return administrator verification.');return proof},
  async roster(signal?:AbortSignal){const x=r(await req('/identity/roster',{signal}));return Array.isArray(x.members)?x.members.map(member):[]},
  change(id:string,kind:'change_role'|'suspend'|'reactivate',version:number,role?:string,proof?:string){return req('/identity/memberships/change',{method:'POST',body:JSON.stringify({id,kind,version,...(role?{role}:{}),...(proof?{bootstrap_eligibility:proof}:{})})})},
  async invitations(signal?:AbortSignal){const x=r(await req('/identity/invitations',{signal}));return Array.isArray(x.invitations)?x.invitations.map(invite):[]},
  createInvitation(recipient:string,role:string,proof?:string){return req('/identity/invitations',{method:'POST',body:JSON.stringify({recipient,role,...(proof?{bootstrap_eligibility:proof}:{})})}) as Promise<unknown>},
  revokeInvitation(id:string,version:number,proof?:string){return req('/identity/invitations/revoke',{method:'POST',body:JSON.stringify({id,version,...(proof?{bootstrap_eligibility:proof}:{})})})},
}
