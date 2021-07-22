(async function() {
    const xsrf = Roblox.XsrfToken.getToken()
    let ticket = (await fetch (
        'https://auth.roblox.com/v1/authentication-ticket',
        {
            credentials:'include',
            method:'POST',
            headers:{
                'x-csrf-token':xsrf
            }
        }
    )).headers.get('rbx-authentication-ticket')
    console.log(ticket)
})()
