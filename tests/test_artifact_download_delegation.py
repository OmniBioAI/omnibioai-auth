"""Exact input scope uses real Auth issuance/persistence and revocation logic."""
import hashlib
import uuid
from datetime import datetime, timedelta

import pytest
from app.core.jwt import decode_token_for_audience, _sign
from app.db.models import DelegatedExecutionGrant, OAuthClient, Organization, OrganizationMembership, User
from app.db.session import SessionLocal as Session
from test_artifact_delegation import setup, header, introspect

REF = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'


def download_context(client):
    data = setup(client, service_scopes=['artifact.delegate', 'artifact.promote', 'artifact.download'],
                 user_permissions=['artifact.promote', 'artifact.download'])
    # setup's OAuth request intentionally requests promotion. Acquire a separate
    # download service bearer through the actual OAuth endpoint.
    secret = uuid.uuid4().hex
    with Session() as db:
        row = db.query(OAuthClient).filter_by(client_id=data['client_id']).one()
        row.client_secret_hash = hashlib.sha256(secret.encode()).hexdigest()
        db.commit()
    response = client.post('/oauth/token', data={'grant_type': 'client_credentials',
        'client_id': data['client_id'], 'client_secret': secret,
        'scope': 'artifact.delegate artifact.download'})
    assert response.status_code == 200
    data['download_service'] = response.json()['access_token']
    return data


def issue_download(client, data, **changes):
    body = dict(initiating_token=data['user'], organization_id=data['org']['id'],
                project_id='8101', run_id='consumer-run', artifact_ids=[REF],
                permissions=['artifact.download'], audience='omnibioai-artifact-manager')
    body.update(changes)
    return client.post('/service/delegations/artifact', json=body, headers=header(data['download_service']))


def test_exact_download_contract(client):
    data = download_context(client)
    response = issue_download(client, data)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body['artifact_ids'] == [REF]
    assert body['run_id'] == 'consumer-run'
    assert body['organization_id'] == str(data['org']['id'])
    claims = decode_token_for_audience(body['access_token'], body['audience'])
    assert claims['output_ids'] == [] and claims['artifact_ids'] == [REF]
    assert introspect(client, body['access_token']).json()['valid'] is True
    assert client.post('/auth/validate', json={'token': body['access_token']}).json()['valid'] is False


@pytest.mark.parametrize('change', [dict(artifact_ids=[]), dict(artifact_ids=[REF,REF]),
    dict(artifact_ids=['../payload']), dict(output_ids=['result']), dict(audience='omnibioai-platform'),
    dict(permissions=['artifact.download','artifact.promote']), dict(user_id='999')])
def test_scope_denials(client, change):
    assert issue_download(client, download_context(client), **change).status_code in (400,422)


@pytest.mark.parametrize('mode', ['grant','expiry','service','scope','organization','membership','user'])
def test_live_state_denies(client, mode):
    data = download_context(client)
    token = issue_download(client, data).json()['access_token']
    claims = decode_token_for_audience(token, 'omnibioai-artifact-manager')
    with Session() as db:
        grant = db.query(DelegatedExecutionGrant).filter_by(delegation_id=claims['jti']).one()
        if mode == 'grant': grant.revoked_at = datetime.utcnow()
        elif mode == 'expiry': grant.expires_at = datetime.utcnow() - timedelta(seconds=1)
        elif mode == 'service': db.query(OAuthClient).filter_by(client_id=data['client_id']).one().status = 'disabled'
        elif mode == 'scope': db.query(OAuthClient).filter_by(client_id=data['client_id']).one().scopes = ['artifact.delegate']
        elif mode == 'organization': db.query(Organization).filter_by(id=grant.organization_id).one().status = 'inactive'
        elif mode == 'membership': db.query(OrganizationMembership).filter_by(user_id=grant.user_id,organization_id=grant.organization_id).one().status = 'inactive'
        elif mode == 'user': db.query(User).filter_by(id=grant.user_id).one().status = 'disabled'
        db.commit()
    assert introspect(client, token).json()['valid'] is False


@pytest.mark.parametrize('changes', [{'artifact_ids':['bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb']},
    {'sub':'999'}, {'org_id':999}, {'project_id':'99'}, {'run_id':'other'},
    {'aud':'omnibioai-platform'}, {'exp':1}, {'permissions':['artifact.promote']}])
def test_signed_conflicting_claims_denied(client, changes):
    data = download_context(client)
    token = issue_download(client, data).json()['access_token']
    claims = decode_token_for_audience(token, 'omnibioai-artifact-manager')
    claims.update(changes)
    assert introspect(client, _sign(claims)).json()['valid'] is False

@pytest.mark.parametrize('mode', ['valid','wrong_run','wrong_project','revoked','raw_ids'])
def test_promotion_provenance_requires_matching_live_download_proof(client, mode):
    data=download_context(client)
    response=issue_download(client,data).json()
    source=response['access_token']
    body=dict(initiating_token=data['user'],organization_id=data['org']['id'],project_id='8101',
              run_id='consumer-run',output_ids=['result'],permissions=['artifact.promote'],
              audience='omnibioai-artifact-manager',source_delegation_token=source)
    if mode=='wrong_run': body['run_id']='other'
    if mode=='wrong_project': body['project_id']='999'
    if mode=='raw_ids': body.update(artifact_ids=[REF],source_delegation_token=None)
    if mode=='revoked':
        with Session() as db:
            db.query(DelegatedExecutionGrant).filter_by(delegation_id=response['delegation_id']).one().revoked_at=datetime.utcnow()
            db.commit()
    result=client.post('/service/delegations/artifact',headers=header(data['service']),json=body)
    if mode=='valid':
        assert result.status_code==200,result.text
        identity=introspect(client,result.json()['access_token']).json()
        assert identity['permissions']==['artifact.promote'] and identity['artifact_ids']==[REF]
    else:
        assert result.status_code in (400,403)


@pytest.mark.parametrize('field', ['iss', 'aud', 'exp', 'jti'])
@pytest.mark.parametrize('permission', ['artifact.download', 'artifact.promote'])
def test_initiating_identity_requires_complete_claims(client, field, permission):
    from jose import jwt
    from app.core.config import settings
    from test_artifact_delegation import issue

    data = download_context(client)
    claims = decode_token_for_audience(data['user'], settings.JWT_AUDIENCE)
    claims.pop(field)
    # Sign the incomplete claims directly: _sign restores issuer/audience.
    token = jwt.encode(claims, settings.SECRET_KEY, algorithm='HS256')
    if permission == 'artifact.download':
        response = issue_download(client, data, initiating_token=token)
    else:
        response = issue(client, data, initiating_token=token)
    assert response.status_code == 403


@pytest.mark.parametrize('changes', [
    {'iss': 'other-issuer'}, {'aud': 'other-audience'}, {'exp': 1},
    {'exp': '9999999999'}, {'jti': ''}, {'sub': ''}, {'sub': '0'},
    {'sub': '1.0'}, {'type': 'refresh'}, {'auth_method': 'client_credentials'},
])
def test_initiating_identity_rejects_malformed_or_expired_claims(client, changes):
    from jose import jwt
    from app.core.config import settings

    data = download_context(client)
    claims = decode_token_for_audience(data['user'], settings.JWT_AUDIENCE)
    claims.update(changes)
    token = jwt.encode(claims, settings.SECRET_KEY, algorithm='HS256')
    assert issue_download(client, data, initiating_token=token).status_code == 403


@pytest.mark.parametrize('changes', [
    {'permissions': []}, {'permissions': None}, {'permissions': ['artifact.download', 'artifact.download']},
    {'permissions': [['artifact.download']]}, {'permissions': [{'permission': 'artifact.download'}]},
    {'permissions': ['artifact.download ']}, {'source_delegation_token': 'malformed'},
])
def test_malformed_permission_and_source_contract_denied(client, changes):
    assert issue_download(client, download_context(client), **changes).status_code in (400, 403, 422)
