import base64
import hashlib
import os
from uuid import uuid4

import requests
from django.http import JsonResponse
from django.views.decorators.clickjacking import xframe_options_exempt


@xframe_options_exempt
def launch(request):
    iss = request.GET["iss"]
    launch = request.GET["launch"]

    # get auth url from iss metadata
    response = requests.get(url=iss + "/metadata", params={"_format": "json"})
    auth_url = response.json()["rest"][0]["security"]["extension"][0]["extension"][0][
        "valueUri"
    ]

    # create a uuid to id the state. pretend we save it for later
    state = str(uuid4())

    code_verifier = base64.urlsafe_b64encode(os.urandom(64)).decode("utf-8").rstrip("=")
    code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = (
        base64.urlsafe_b64encode(code_challenge).decode("utf-8").rstrip("=")
    )

    response = requests.get(
        url=auth_url,
        params={
            "response_type": "code",
            "client_id": os.environ["ECW_CLIENT_ID"],
            "redirect_uri": os.environ["ECW_REDIRECT_URL"],
            # scopes from documentation example
            "scopes": "launch openid fhirUser offline_access user/Encounter.read user/Patient.read",
            "state": state,
            "aud": iss,
            "launch": launch,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        },
    )

    # return auth url response for debugging
    return JsonResponse(response.json())
