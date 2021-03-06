from django.shortcuts import render
from django.contrib.auth.decorators import login_required

import json


def index(request):
    return render(request, 'index.html')


@login_required
def dashboard(request):
    user = request.user
    auth0user = user.social_auth.get(provider="auth0")
    userdata = {
        'user_id': auth0user.uid,
        'username': user.username,
        'name': user.first_name,
        'picture': auth0user.extra_data['picture'],
        'contact_id': auth0user.extra_data['contact_id'],
        'tags': auth0user.extra_data['tags']
    }

    return render(request, 'dashboard.html', {
        'auth0User': auth0user,
        'userdata': json.dumps(userdata, indent=4)
    })
