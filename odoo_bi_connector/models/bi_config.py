from odoo import models, fields, api, _
from odoo.exceptions import ValidationError


class BiConfig(models.Model):
    _name = 'bi.config'
    _description = 'BI Connector Configuration'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _rec_name = 'name'

    name = fields.Char(string='Configuration Name', required=True, tracking=True)
    jwt_secret = fields.Char(
        string='JWT Secret Key',
        required=True,
        help='Secret key used to sign JWT tokens. Keep this secure.',
    )
    token_expiry = fields.Integer(
        string='Token Expiry (seconds)',
        default=3600,
        help='How long JWT tokens remain valid in seconds.',
    )
    rate_limit = fields.Integer(
        string='Rate Limit (req/hour)',
        default=1000,
        help='Maximum API requests allowed per hour per token.',
    )
    allowed_origins = fields.Text(
        string='Allowed Origins (CORS)',
        help='One origin per line. Example: https://app.powerbi.com',
    )
    active = fields.Boolean(default=True, tracking=True)
    odata_enabled = fields.Boolean(
        string='OData Enabled',
        default=True,
        help='Enable OData v4 endpoint for Power BI and Excel.',
    )
    rest_enabled = fields.Boolean(
        string='REST API Enabled',
        default=True,
        help='Enable REST JSON API endpoint.',
    )
    log_requests = fields.Boolean(
        string='Log API Requests',
        default=True,
        help='Log all incoming API requests for auditing.',
    )
    company_id = fields.Many2one(
        'res.company',
        string='Company',
        default=lambda self: self.env.company,
    )
    endpoint_ids = fields.One2many(
        'bi.endpoint',
        'config_id',
        string='Endpoints',
    )
    token_ids = fields.One2many(
        'bi.token',
        'config_id',
        string='Access Tokens',
    )
    log_ids = fields.One2many(
        'bi.log',
        'config_id',
        string='Access Logs',
    )
    endpoint_count = fields.Integer(
        string='Endpoint Count',
        compute='_compute_counts',
    )
    token_count = fields.Integer(
        string='Token Count',
        compute='_compute_counts',
    )
    log_count = fields.Integer(
        string='Log Count',
        compute='_compute_counts',
    )

    @api.depends('endpoint_ids', 'token_ids', 'log_ids')
    def _compute_counts(self):
        for rec in self:
            rec.endpoint_count = len(rec.endpoint_ids)
            rec.token_count = len(rec.token_ids)
            rec.log_count = len(rec.log_ids)

    def action_view_endpoints(self):
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': 'Endpoints',
            'res_model': 'bi.endpoint',
            'view_mode': 'list,form',
            'domain': [('config_id', '=', self.id)],
            'context': {'default_config_id': self.id},
        }

    def action_view_tokens(self):
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': 'Access Tokens',
            'res_model': 'bi.token',
            'view_mode': 'list,form',
            'domain': [('config_id', '=', self.id)],
            'context': {'default_config_id': self.id},
        }

    def action_view_logs(self):
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': 'Access Logs',
            'res_model': 'bi.log',
            'view_mode': 'list,form',
            'domain': [('config_id', '=', self.id)],
        }

    @api.constrains('active', 'company_id')
    def _check_single_active_config(self):
        for rec in self:
            if rec.active:
                domain = [
                    ('active', '=', True),
                    ('company_id', '=', rec.company_id.id),
                    ('id', '!=', rec.id),
                ]
                if self.search_count(domain):
                    raise ValidationError(
                        _('Only one active BI configuration is allowed per company.')
                    )
