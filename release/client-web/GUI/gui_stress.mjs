import { chromium } from 'playwright';
const url=process.env.GUI_URL, loops=Number(process.env.GUI_LOOPS||1000), errors=[];
const browser=await chromium.launch({headless:true}); const page=await browser.newPage();
page.on('pageerror',e=>errors.push('pageerror: '+e.message));
page.on('console',m=>{if(m.type()==='error')errors.push('console: '+m.text())});
page.on('requestfailed',r=>errors.push('requestfailed: '+r.url()+' :: '+(r.failure()?.errorText||'')));
await page.goto(url,{waitUntil:'domcontentloaded',timeout:15000}); await page.waitForTimeout(1000);
const skip=/delete|remove|xóa|logout|đăng xuất|submit|protect|restore|encrypt|decrypt|upload|download|choose file|chọn file|exit/i;
for(let i=0;i<loops;i++){
 const els=await page.locator('button,[role="button"],a,input[type="button"]').all(); let clicked=false;
 for(const el of els){try{if(!(await el.isVisible()))continue;const t=((await el.innerText().catch(()=>''))+' '+(await el.getAttribute('aria-label').catch(()=>''))).trim();if(!t||skip.test(t))continue;await el.click({timeout:1000});clicked=true;break}catch{}}
 if(!clicked){const inp=page.locator('input:not([type="password"]):not([type="file"])').first();if(await inp.count()&&await inp.isVisible().catch(()=>false)){try{await inp.fill('stress-'+i);await inp.press('Escape').catch(()=>{})}catch{}}}
 if(errors.length)break; if((i+1)%100===0)console.log(`GUI stress: ${i+1}/${loops}`);
}
await page.screenshot({path:process.env.GUI_STRESS_SCREENSHOT||'sentinelgate-gui-stress.png',fullPage:true}).catch(()=>{});await browser.close();
if(errors.length){console.error('GUI_STRESS_ERRORS');for(const e of errors.slice(0,30))console.error(e);process.exit(1)}console.log(`GUI stress completed: ${loops} iterations`);
