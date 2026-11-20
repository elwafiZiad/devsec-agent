document.getElementById('demo-form').addEventListener('submit',async event=>{event.preventDefault();const form=event.currentTarget,button=form.querySelector('button'),result=document.getElementById('result');button.disabled=true;try{const response=await fetch('/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:form.username.value,password:form.password.value})});if(!response.ok)throw Error();const data=await response.json();result.hidden=false;result.className='notice'+(data.success?'':' error');result.textContent=data.message+' Événement : '+data.event_id+' — visible dans le tableau de bord sous quelques secondes.';form.password.value='';}catch{result.hidden=false;result.className='notice error';result.textContent='La tentative n’a pas pu être enregistrée. Vérifie que le service fonctionne.';}finally{button.disabled=false;}});

document.getElementById('simulate-r3').onclick = async function () {
    this.disabled = true;
    const result = document.getElementById('r3-result');
    try {
        const response = await fetch('/simulation/privileges?scenario='+document.getElementById('scenario-r3').value, {method: 'POST'});
        if (!response.ok) throw Error();
        const data = await response.json();
        result.textContent = 'Simulation enregistrée pour ' + data.user_id + '. Consulte les incidents du tableau de bord.';
    } catch {
        result.textContent = 'Simulation interrompue. Vérifie le service.';
    } finally {
        this.disabled = false;
    }
};

document.getElementById('simulate-r4').onclick = async function () {
    this.disabled = true;
    const result = document.getElementById('r4-result');
    try {
        const account = document.getElementById('r4-account').value;
        const response = await fetch('/simulation/horaire?account='+encodeURIComponent(account), {method:'POST'});
        if (!response.ok) throw Error();
        const event = await response.json();
        result.textContent = 'Connexion simulée pour ' + account + ' · événement ' + event.event_id;
    } catch {
        result.textContent = 'Simulation indisponible.';
    } finally {
        this.disabled = false;
    }
};
