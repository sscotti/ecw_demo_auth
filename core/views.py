import base64
import hashlib
import os
import secrets
from uuid import uuid4

import requests
from django.http import JsonResponse
from django.views.decorators.clickjacking import xframe_options_exempt


@xframe_options_exempt
def launch(request):
    launch_response = request.GET
    iss = launch_response["iss"]
    launch_code = launch_response["launch"]

    # get auth url from iss metadata
    metadata_response = requests.get(url=iss + "/metadata", params={"_format": "json"})
    auth_url = metadata_response.json()["rest"][0]["security"]["extension"][0][
        "extension"
    ][0]["valueUri"]

    # create a uuid to id the state. pretend we save it for later
    state = str(uuid4())

    # b"a33e1e9be0725bf6ab7705f022ea80543d1718b89a0bea35f95e7375bb216e51"
    code_verifier = secrets.token_hex(32).encode("utf-8")
    # b"4da689c0e38bb59f5ba1c452a3d2206c4d74a6473c491f6f2d759ae6fe544d97"
    code_challenge_sha = hashlib.sha256(code_verifier).hexdigest().encode("utf-8")
    # "NGRhNjg5YzBlMzhiYjU5ZjViYTFjNDUyYTNkMjIwNmM0ZDc0YTY0NzNjNDkxZjZmMmQ3NTlhZTZmZTU0NGQ5Nw"
    code_challenge = base64.urlsafe_b64encode(code_challenge_sha).decode("utf-8").rstrip("=")
    print(f"{code_verifier=} {code_challenge_sha=} {code_challenge=}")

    auth_response = requests.get(
        url=auth_url,
        params={
            "response_type": "code",
            "client_id": os.environ["ECW_CLIENT_ID"],
            "redirect_uri": os.environ["ECW_REDIRECT_URL"],
            # scopes from documentation example
            "scope": "launch user/Patient.read user/Encounter.read",
            "state": state,
            "aud": iss,
            "launch": launch_code,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        },
    )
    print(auth_response.url)

    # return responses for debugging
    all_responses = {
        "launch_response": launch_response,
        "metadata_response": metadata_response.json(),
        "auth_response": auth_response.json(),
    }
    return JsonResponse(all_responses)
