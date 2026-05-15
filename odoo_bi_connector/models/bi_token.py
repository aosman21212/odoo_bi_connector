import hmac
import hashlib
import base64
import json
import time

from odoo import models, fields, api, _
from odoo.exceptions import UserError


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


class BiToken(models.Model):
    _name = 'bi.token'
    _description = 'BI Connector Access Token'
    _rec_name = 'name'

    name = fields.Char(string='Token Name', required=True)
    config_id = fields.Many2one(
        'bi.config',
        string='Configuration',
        ondelete='cascade',
    )
    user_id = fields.Many2one(
        'res.users',
        string='Odoo User',
        default=lambda self: self.env.user,
    )
    token = fields.Char(
        string='JWT Token',
        readonly=True,
        help='The generated JWT token. Copy this to your BI tool.',
    )
    expires_at = fields.Datetime(string='Expires At')
    state = fields.Selection(
        [
            ('active', 'Active'),
            ('expired', 'Expired'),
            ('revoked', 'Revoked'),
        ],
        string='State',
        default='active',
    )
    scope = fields.Selection(
        [
            ('full', 'Full Access'),
            ('readonly', 'Read Only'),
            ('endpoint', 'Specific Endpoints'),
        ],
        string='Scope',
        default='readonly',
    )
    endpoint_ids = fields.Many2many(
        'bi.endpoint',
        'bi_token_endpoint_rel',
        'token_id',
        'endpoint_id',
        string='Allowed Endpoints',
        help='If scope is Specific Endpoints, only these endpoints are accessible.',
    )
    last_used = fields.Datetime(string='Last Used', readonly=True)
    use_count = fields.Integer(string='Use Count', default=0, readonly=True)

    def action_generate_token(self):
        """Generate a new JWT token for this record."""
        self.ensure_one()
        if not self.config_id:
            raise UserError(_('Please link this token to a configuration first.'))
        if not self.config_id.jwt_secret:
            raise UserError(_('The configuration must have a JWT Secret Key set.'))

        now = time.time()
        expiry = self.config_id.token_expiry or 3600
        exp = now + expiry

        payload = {
            'iss': 'odoo_bi_connector',
            'sub': str(self.user_id.id or self.env.user.id),
            'iat': int(now),
            'exp': int(exp),
            'scope': self.scope,
            'token_id': self.id,
            'company_id': self.config_id.company_id.id,
        }
        if self.scope == 'endpoint' and self.endpoint_ids:
            payload['endpoints'] = self.endpoint_ids.mapped('technical_name')

        token_str = _generate_jwt(self.config_id.jwt_secret, payload)
        expires_at = fields.Datetime.from_string(
            fields.Datetime.to_string(
                fields.Datetime.now()
            )
        )
        import datetime
        expires_dt = datetime.datetime.utcnow() + datetime.timedelta(seconds=expiry)

        self.write({
            'token': token_str,
            'expires_at': fields.Datetime.to_string(expires_dt),
            'state': 'active',
        })
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Token Generated'),
                'message': _('JWT token has been generated successfully. Copy it from the Token field.'),
                'type': 'success',
                'sticky': False,
            },
        }

    def action_revoke(self):
        """Revoke this token."""
        self.write({'state': 'revoked', 'token': False})
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Token Revoked'),
                'message': _('The token has been revoked and can no longer be used.'),
                'type': 'warning',
                'sticky': False,
            },
        }

    def _check_expired(self):
        """Check if this token has expired and update state accordingly."""
        now = fields.Datetime.now()
        for rec in self:
            if rec.state == 'active' and rec.expires_at and rec.expires_at < now:
                rec.write({'state': 'expired'})

    @api.model
    def _cron_check_expired_tokens(self):
        """Cron job to mark expired tokens."""
        tokens = self.search([('state', '=', 'active')])
        tokens._check_expired()
