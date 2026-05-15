import hmac
import hashlib
import base64
import json
import time
import logging

from odoo import http, fields
from odoo.http import request

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# JWT helpers (no PyJWT dependency)
# ---------------------------------------------------------------------------

def _b64url_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def _b64url_decode(s):
    padding = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + '=' * padding)


def _generate_jwt(secret, payload):
    header = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}))
    body = _b64url_encode(json.dumps(payload))
    signing_input = f"{header}.{body}"
    sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url_encode(sig)}"


def _verify_jwt(secret, token):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        signing_input = f"{parts[0]}.{parts[1]}"
        sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
        expected = _b64url_encode(sig)
        if expected != parts[2]:
            return None
        payload = json.loads(_b64url_decode(parts[1]))
        if payload.get('exp', 0) < time.time():
            return None
        return payload
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_active_config():
    """Return the active bi.config for current company."""
    company_id = request.env.company.id
    config = request.env['bi.config'].sudo().search(
        [('active', '=', True), ('company_id', '=', company_id)],
        limit=1,
    )
    return config


def _authenticate_request():
    """
    Extract and verify Bearer JWT from Authorization header.
    Returns (token_record, payload) or (None, None).
    """
    auth_header = request.httprequest.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return None, None, None

    jwt_str = auth_header[7:].strip()
    config = _get_active_config()
    if not config:
        return None, None, None

    payload = _verify_jwt(config.jwt_secret, jwt_str)
    if not payload:
        return None, None, config

    token_id = payload.get('token_id')
    token_rec = request.env['bi.token'].sudo().browse(token_id)
    if not token_rec.exists() or token_rec.state != 'active':
        return None, None, config

    # Update usage stats
    token_rec.sudo().write({
        'last_used': fields.Datetime.now(),
        'use_count': token_rec.use_count + 1,
    })
    return token_rec, payload, config


def _log_request(config, token, endpoint, status_code, response_time=0,
                 record_count=0, error_message=None):
    """Write an access log entry."""
    if not config or not config.log_requests:
        return
    try:
        request.env['bi.log'].sudo().create({
            'config_id': config.id,
            'token_id': token.id if token else False,
            'endpoint_id': endpoint.id if endpoint else False,
            'ip_address': request.httprequest.remote_addr,
            'method': request.httprequest.method,
            'path': request.httprequest.path,
            'status_code': status_code,
            'response_time': response_time,
            'record_count': record_count,
            'error_message': error_message,
        })
    except Exception as e:
        _logger.warning('BI Connector: failed to write log: %s', e)


def _json_response(data, status=200):
    """Return a JSON HTTP response."""
    body = json.dumps(data)
    return request.make_response(
        body,
        headers=[
            ('Content-Type', 'application/json'),
            ('Access-Control-Allow-Origin', '*'),
            ('Access-Control-Allow-Methods', 'GET, POST, OPTIONS'),
            ('Access-Control-Allow-Headers', 'Authorization, Content-Type'),
        ],
        status=status,
    )


def _error(message, status=400, code=None):
    return _json_response(
        {'success': False, 'error': message, 'code': code or status},
        status=status,
    )


# ---------------------------------------------------------------------------
# Controller
# ---------------------------------------------------------------------------

class BiConnectorController(http.Controller):

    # ------------------------------------------------------------------
    # OPTIONS preflight (CORS)
    # ------------------------------------------------------------------

    @http.route(
        ['/api/bi/v1/<path:subpath>'],
        type='http',
        auth='none',
        methods=['OPTIONS'],
        csrf=False,
        save_session=False,
    )
    def options_preflight(self, subpath, **kwargs):
        return request.make_response(
            '',
            headers=[
                ('Access-Control-Allow-Origin', '*'),
                ('Access-Control-Allow-Methods', 'GET, POST, OPTIONS'),
                ('Access-Control-Allow-Headers', 'Authorization, Content-Type'),
                ('Access-Control-Max-Age', '86400'),
            ],
        )

    # ------------------------------------------------------------------
    # POST /api/bi/v1/token  — issue a JWT
    # ------------------------------------------------------------------

    @http.route(
        '/api/bi/v1/token',
        type='http',
        auth='none',
        methods=['POST'],
        csrf=False,
        save_session=False,
    )
    def issue_token(self, **kwargs):
        start = time.time()
        config = _get_active_config()
        if not config:
            return _error('No active BI configuration found.', 503)

        try:
            body = json.loads(request.httprequest.data or '{}')
        except Exception:
            body = {}

        # Support: {"token_name": "...", "user_login": "...", "password": "..."}
        # or Basic Auth
        user_login = body.get('user_login') or ''
        password = body.get('password') or ''

        # Basic Auth fallback
        auth_header = request.httprequest.headers.get('Authorization', '')
        if auth_header.startswith('Basic '):
            try:
                decoded = base64.b64decode(auth_header[6:]).decode()
                user_login, password = decoded.split(':', 1)
            except Exception:
                pass

        # Authenticate the Odoo user
        db = request.db
        uid = request.session.authenticate(db, user_login, password)
        if not uid:
            elapsed = (time.time() - start) * 1000
            _log_request(config, None, None, 401, elapsed, 0, 'Invalid credentials')
            return _error('Invalid credentials.', 401)

        user = request.env['res.users'].sudo().browse(uid)
        token_name = body.get('token_name') or f'API Token - {user.name}'
        expiry = config.token_expiry or 3600

        # Create a bi.token record
        token_rec = request.env['bi.token'].sudo().create({
            'name': token_name,
            'config_id': config.id,
            'user_id': uid,
            'scope': body.get('scope', 'readonly'),
        })
        token_rec.action_generate_token()

        elapsed = (time.time() - start) * 1000
        _log_request(config, token_rec, None, 200, elapsed)

        return _json_response({
            'access_token': token_rec.token,
            'expires_in': expiry,
            'token_type': 'Bearer',
            'token_id': token_rec.id,
        })

    # ------------------------------------------------------------------
    # POST /api/bi/v1/token/revoke
    # ------------------------------------------------------------------

    @http.route(
        '/api/bi/v1/token/revoke',
        type='http',
        auth='none',
        methods=['POST'],
        csrf=False,
        save_session=False,
    )
    def revoke_token(self, **kwargs):
        start = time.time()
        token_rec, payload, config = _authenticate_request()
        if not token_rec:
            return _error('Unauthorized.', 401)

        token_rec.sudo().action_revoke()
        elapsed = (time.time() - start) * 1000
        _log_request(config, token_rec, None, 200, elapsed)
        return _json_response({'success': True, 'message': 'Token revoked.'})

    # ------------------------------------------------------------------
    # GET /api/bi/v1/odata  — OData service document
    # ------------------------------------------------------------------

    @http.route(
        '/api/bi/v1/odata',
        type='http',
        auth='none',
        methods=['GET'],
        csrf=False,
        save_session=False,
    )
    def odata_service_doc(self, **kwargs):
        start = time.time()
        token_rec, payload, config = _authenticate_request()
        if not token_rec:
            return _error('Unauthorized.', 401)
        if not config.odata_enabled:
            return _error('OData endpoint is disabled.', 403)

        base_url = request.httprequest.url_root.rstrip('/')
        endpoints = request.env['bi.endpoint'].sudo().search([
            ('config_id', '=', config.id),
            ('state', '=', 'active'),
            ('active', '=', True),
        ])

        value = []
        for ep in endpoints:
            value.append({
                'name': ep.technical_name,
                'kind': 'EntitySet',
                'url': f'{base_url}/api/bi/v1/odata/{ep.technical_name}',
            })

        doc = {
            '@odata.context': f'{base_url}/api/bi/v1/odata/$metadata',
            'value': value,
        }
        elapsed = (time.time() - start) * 1000
        _log_request(config, token_rec, None, 200, elapsed)
        return _json_response(doc)

    # ------------------------------------------------------------------
    # GET /api/bi/v1/odata/<endpoint_name>  — OData entity set
    # ------------------------------------------------------------------

    @http.route(
        '/api/bi/v1/odata/<string:endpoint_name>',
        type='http',
        auth='none',
        methods=['GET'],
        csrf=False,
        save_session=False,
    )
    def odata_entity_set(self, endpoint_name, **kwargs):
        start = time.time()
        token_rec, payload, config = _authenticate_request()
        if not token_rec:
            return _error('Unauthorized.', 401)
        if not config.odata_enabled:
            return _error('OData endpoint is disabled.', 403)

        endpoint = request.env['bi.endpoint'].sudo().search([
            ('technical_name', '=', endpoint_name),
            ('state', '=', 'active'),
            ('active', '=', True),
        ], limit=1)
        if not endpoint:
            return _error(f'Endpoint "{endpoint_name}" not found.', 404)

        # Check scope
        if payload.get('scope') == 'endpoint':
            allowed = payload.get('endpoints', [])
            if endpoint_name not in allowed:
                return _error('Access to this endpoint is not permitted.', 403)

        # OData query params: $top, $skip, $filter (basic support)
        params = request.httprequest.args
        limit = int(params.get('$top', endpoint.limit))
        offset = int(params.get('$skip', 0))

        try:
            records = endpoint._fetch_data(limit=limit, offset=offset)
        except Exception as e:
            elapsed = (time.time() - start) * 1000
            _log_request(config, token_rec, endpoint, 500, elapsed, 0, str(e))
            return _error(f'Data fetch error: {e}', 500)

        endpoint._increment_call_count()
        base_url = request.httprequest.url_root.rstrip('/')
        result = {
            '@odata.context': f'{base_url}/api/bi/v1/odata/$metadata#{endpoint_name}',
            '@odata.count': len(records),
            'value': records,
        }
        elapsed = (time.time() - start) * 1000
        _log_request(config, token_rec, endpoint, 200, elapsed, len(records))
        return _json_response(result)

    # ------------------------------------------------------------------
    # GET /api/bi/v1/data/<endpoint_name>  — REST JSON
    # ------------------------------------------------------------------

    @http.route(
        '/api/bi/v1/data/<string:endpoint_name>',
        type='http',
        auth='none',
        methods=['GET'],
        csrf=False,
        save_session=False,
    )
    def rest_data(self, endpoint_name, **kwargs):
        start = time.time()
        token_rec, payload, config = _authenticate_request()
        if not token_rec:
            return _error('Unauthorized.', 401)
        if not config.rest_enabled:
            return _error('REST API endpoint is disabled.', 403)

        endpoint = request.env['bi.endpoint'].sudo().search([
            ('technical_name', '=', endpoint_name),
            ('state', '=', 'active'),
            ('active', '=', True),
        ], limit=1)
        if not endpoint:
            return _error(f'Endpoint "{endpoint_name}" not found.', 404)

        # Check scope
        if payload.get('scope') == 'endpoint':
            allowed = payload.get('endpoints', [])
            if endpoint_name not in allowed:
                return _error('Access to this endpoint is not permitted.', 403)

        params = request.httprequest.args
        limit = int(params.get('limit', endpoint.limit))
        offset = int(params.get('offset', 0))
        order = params.get('order', None)
        domain_str = params.get('domain', None)

        try:
            records = endpoint._fetch_data(
                limit=limit,
                offset=offset,
                domain=domain_str,
                order=order,
            )
        except Exception as e:
            elapsed = (time.time() - start) * 1000
            _log_request(config, token_rec, endpoint, 500, elapsed, 0, str(e))
            return _error(f'Data fetch error: {e}', 500)

        endpoint._increment_call_count()
        elapsed = (time.time() - start) * 1000
        _log_request(config, token_rec, endpoint, 200, elapsed, len(records))

        return _json_response({
            'success': True,
            'endpoint': endpoint_name,
            'count': len(records),
            'offset': offset,
            'limit': limit,
            'data': records,
        })

    # ------------------------------------------------------------------
    # GET /api/bi/v1/schema/<endpoint_name>
    # ------------------------------------------------------------------

    @http.route(
        '/api/bi/v1/schema/<string:endpoint_name>',
        type='http',
        auth='none',
        methods=['GET'],
        csrf=False,
        save_session=False,
    )
    def endpoint_schema(self, endpoint_name, **kwargs):
        start = time.time()
        token_rec, payload, config = _authenticate_request()
        if not token_rec:
            return _error('Unauthorized.', 401)

        endpoint = request.env['bi.endpoint'].sudo().search([
            ('technical_name', '=', endpoint_name),
            ('state', '=', 'active'),
            ('active', '=', True),
        ], limit=1)
        if not endpoint:
            return _error(f'Endpoint "{endpoint_name}" not found.', 404)

        model = request.env[endpoint.model_id.model].sudo()
        field_names = endpoint._get_field_names()

        schema = []
        for fname in field_names:
            if fname not in model._fields:
                continue
            f = model._fields[fname]
            schema.append({
                'name': fname,
                'type': f.type,
                'string': f.string,
                'required': bool(getattr(f, 'required', False)),
                'readonly': bool(getattr(f, 'readonly', False)),
            })

        elapsed = (time.time() - start) * 1000
        _log_request(config, token_rec, endpoint, 200, elapsed)

        return _json_response({
            'success': True,
            'endpoint': endpoint_name,
            'model': endpoint.model_id.model,
            'fields': schema,
        })

    # ------------------------------------------------------------------
    # GET /api/bi/v1/health  — health check (no auth)
    # ------------------------------------------------------------------

    @http.route(
        '/api/bi/v1/health',
        type='http',
        auth='none',
        methods=['GET'],
        csrf=False,
        save_session=False,
    )
    def health_check(self, **kwargs):
        config = _get_active_config()
        return _json_response({
            'status': 'ok',
            'service': 'BI Connector',
            'version': '19.0.1.0.0',
            'configured': bool(config),
            'timestamp': time.time(),
        })
