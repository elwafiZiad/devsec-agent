const $ = id => document.getElementById(id);
let selectedIp = "";
let before = null, nextCursor = null, busy = false;
let incidentBefore=null, incidentNext=null;
const fmt = text => new Date(text).toLocaleString('fr-FR', {hour12:false});
async function get(url){const r=await fetch(url);if(r.status===401){location.href='/login';throw Error('Connexion expirée');}if(r.status===422)throw Error('Adresse IP invalide');if(!r.ok)throw Error('API indisponible');return r.json();}
function cell(row,text){const c=document.createElement('td');c.textContent=text;row.appendChild(c);return c;}
async function refresh(){if(busy)return;busy=true;try{
 const params=new URLSearchParams();if($('filter').value)params.set('event_type',$('filter').value);if(selectedIp)params.set('source_ip',selectedIp);if(before)params.set('before',before);
 const [data,s,inc,ci]=await Promise.all([get('/events?'+params),get('/stats'),get('/incidents'+(incidentBefore?'?before='+incidentBefore:'')),get('/ci/incidents')]); renderCI(ci.items); renderIncidents(inc,s.incidents);
 $('total').textContent=s.total;$('failures').textContent=s.failures;$('successes').textContent=s.successes;$('storage').textContent=s.storage==='postgresql'?'PostgreSQL':'SQLite · local';
 const c=s.collector, active=c&&(Date.now()-Date.parse(c.last_seen_at))<15000;
 $('connection').textContent=active?'● Collecteur actif':'○ Collecteur en attente';
 $('collector-status').textContent=c?`Collecteur du laboratoire · dernier contact ${fmt(c.last_seen_at)} · ${c.pending} en attente · ${c.quarantined} en quarantaine`:'Aucun contact reçu du collecteur.';
 const body=$('events');body.replaceChildren();
 for(const item of data.items){const row=document.createElement('tr');cell(row,fmt(item.event_time));const badge=document.createElement('span');badge.className='badge '+(item.outcome || '');badge.textContent=item.event_type==='audit.task_granted'?'Autorisation · '+item.operation:item.event_type==='audit.task_action'?(item.result==='executed'?'Exécutée · ':'Refusée · ')+item.operation:item.event_type==='audit.role_change'?item.old_role+' → '+item.new_role:item.event_type==='audit.sensitive_action'?item.operation:item.event_type==='http.access'?'HTTP '+item.status_code:item.outcome==='failure'?'Refusée':(item.schedule ? 'Acceptée · '+item.schedule.status : 'Acceptée');cell(row,'').appendChild(badge);cell(row,item.source_ip);cell(row,item.path ? item.method+' '+item.path : '—');cell(row,item.user_id || '—');const b=document.createElement('button');b.className='subtle';b.textContent='Voir le log';b.onclick=()=>{$('payload').textContent=JSON.stringify(item,null,2);$('detail').hidden=false;$('detail').scrollIntoView({behavior:'smooth',block:'nearest'});};cell(row,'').appendChild(b);body.appendChild(row);}
 $('empty').hidden=data.items.length>0;nextCursor=data.next_cursor;$('older').hidden=!nextCursor;$('latest').hidden=!before;$('updated').textContent='Actualisé à '+new Date().toLocaleTimeString('fr-FR')+' · heures locales';
 }catch(e){if(e.message==='Adresse IP invalide'){$('ip-error').textContent=e.message;$('events').replaceChildren();$('older').hidden=true;return;}$('connection').textContent='○ Connexion interrompue';$('collector-status').textContent='Impossible de récupérer les données. Nouvelle tentative automatique dans 3 secondes.';}finally{busy=false;}}
$('ip-form').onsubmit=e=>{e.preventDefault();selectedIp=$('ip').value.trim();$('ip-error').textContent='';before=null;refresh();};
$('filter').onchange=()=>{before=null;refresh();};$('older').onclick=()=>{before=nextCursor;refresh();};$('latest').onclick=()=>{before=null;refresh();};$('close-detail').onclick=()=>{$('detail').hidden=true;};refresh();setInterval(refresh,3000);


function renderIncidents(data,total){
 $('incident-count').textContent=total;
 const list=$('incident-list');list.replaceChildren();
 if(!data.items.length){const p=document.createElement('p');p.className='source-status';p.textContent='Aucun incident détecté.';list.appendChild(p);}
 for(const incident of data.items){const item=document.createElement('div');item.className='incident-row';const text=document.createElement('div');const title=document.createElement('strong');const http = incident.rule === 'R2';
 title.textContent=(http ? 'R2 · Scan HTTP possible · #' : 'R1 · Échecs de connexion répétés · #')+incident.id;const sub=document.createElement('p');sub.textContent=http ? incident.source_ip+' · '+incident.service+' · pic de '+incident.peak_count+' routes / 60 s · '+fmt(incident.last_event_at) : incident.user_id+' · '+incident.source_ip+' · pic de '+incident.peak_count+' échecs / 5 min · '+fmt(incident.last_event_at);if (incident.rule === 'R3') {
     title.textContent = 'R3 · Privilèges à examiner · #' + incident.id;
     sub.textContent = incident.user_id + ' · ' + incident.service + ' · ' + fmt(incident.last_event_at);
 } else if (incident.rule === 'R4') {
     title.textContent = 'R4 · Connexion hors planning · #' + incident.id;
     sub.textContent = 'Gravité faible · ' + incident.user_id + ' · ' + fmt(incident.last_event_at);
 }text.append(title,sub);const button=document.createElement('button');button.className='subtle';button.textContent='Voir les preuves';button.onclick=async()=>{try{const detail=await get('/incidents/'+incident.id);$('payload').textContent=JSON.stringify(detail,null,2);$('detail').hidden=false;$('detail').scrollIntoView({behavior:'smooth',block:'nearest'});}catch{$('connection').textContent='Incident actualisé : recharge la liste.';}};item.append(text,button);list.appendChild(item);}
 incidentNext=data.next_cursor;$('incidents-older').hidden=!incidentNext;$('incidents-latest').hidden=!incidentBefore;
}
$('incidents-older').onclick=()=>{incidentBefore=incidentNext;refresh();};$('incidents-latest').onclick=()=>{incidentBefore=null;refresh();};

function renderCI(items) {
 const list = $('ci-list');
 list.replaceChildren();
 if (!items.length) list.textContent = 'Aucun échec CI importé.';
 for (const item of items) {
   const article = document.createElement('article');
   const title = document.createElement('strong');
   title.textContent = item.test || item.step;
   const meta = document.createElement('p');
   meta.textContent = [item.repo, item.branch, item.sha, item.job, item.step].join(' · ');
   const proof = document.createElement('pre');
   proof.textContent = item.evidence;
   const link = document.createElement('a');
   link.href = item.url;
   link.textContent = 'Voir la tentative sur GitHub';
   link.target = '_blank';
   link.rel = 'noopener';
   article.append(title, meta, proof, link);
   list.appendChild(article);
 }
}
