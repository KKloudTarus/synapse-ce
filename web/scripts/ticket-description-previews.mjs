// Capture actual native-serializer fixture bytes without contacting providers.
import { chromium } from '@playwright/test'
import {readFileSync,writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import { resolve } from 'node:path';
const dir=resolve('../docs/evidence/remaining-providers/ticket-rendering');
const html=readFileSync(`${dir}/azure-description.html`,'utf8');
const browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
try {
 const page=await browser.newPage({viewport:{width:1100,height:650}});
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.route('**/*',route=>route.abort());
 await page.setContent(html);
 if(await page.locator('a').count()!==1||await page.locator('script,img').count()!==0)throw Error('unexpected active content');
 await page.screenshot({path:`${dir}/azure-description.png`,fullPage:true});
 const manifest={kind:'local_serializer_preview',native_acceptance:false,source:'TestAzureDescriptionRendersSafeHTMLAtPayloadBoundary output',browser_errors:errors,files:['azure-description.html','azure-description.png'].map(file=>({file,sha256:createHash('sha256').update(readFileSync(`${dir}/${file}`)).digest('hex')}))};
 writeFileSync(`${dir}/manifest.json`,JSON.stringify(manifest,null,2)+'\n');
 if(errors.length)throw Error('browser errors');
} finally {await browser.close();}
