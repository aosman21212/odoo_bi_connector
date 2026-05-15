from odoo import models, fields, api, _
from odoo.exceptions import ValidationError


class BiEndpoint(models.Model):
    _name = 'bi.endpoint'
    _description = 'BI Connector Endpoint'
    _rec_name = 'name'

    name = fields.Char(string='Endpoint Name', required=True)
    technical_name = fields.Char(
        string='Technical Name',
        required=True,
        help='Used in the API URL: /api/bi/v1/data/<technical_name>',
    )
    config_id = fields.Many2one(
        'bi.config',
        string='Configuration',
        ondelete='cascade',
    )
    model_id = fields.Many2one(
        'ir.model',
        string='Odoo Model',
        required=True,
        ondelete='cascade',
        help='The Odoo model to expose via this endpoint.',
    )
    model_name = fields.Char(
        related='model_id.model',
        string='Model Technical Name',
        store=True,
    )
    domain = fields.Char(
        string='Filter Domain',
        default='[]',
        help='Python domain expression to filter records.',
    )
    field_ids = fields.Many2many(
        'ir.model.fields',
        'bi_endpoint_field_rel',
        'endpoint_id',
        'field_id',
        string='Exposed Fields',
        domain="[('model_id', '=', model_id)]",
        help='Select which fields to expose. Leave empty to expose all fields.',
    )
    limit = fields.Integer(
        string='Record Limit',
        default=10000,
        help='Maximum number of records returned per request.',
    )
    order_by = fields.Char(
        string='Order By',
        default='id desc',
        help='SQL order clause, e.g. "id desc" or "name asc".',
    )
    active = fields.Boolean(default=True)
    description = fields.Text(string='Description')
    last_called = fields.Datetime(string='Last Called', readonly=True)
    call_count = fields.Integer(string='Call Count', readonly=True, default=0)
    state = fields.Selection(
        [
            ('draft', 'Draft'),
            ('active', 'Active'),
            ('suspended', 'Suspended'),
        ],
        string='State',
        default='draft',
    )

    _technical_name_unique = models.Constraint(
        'UNIQUE(technical_name)',
        'The technical name must be unique across all endpoints.',
    )

    def action_activate(self):
        self.write({'state': 'active'})

    def action_suspend(self):
        self.write({'state': 'suspended'})

    def action_draft(self):
        self.write({'state': 'draft'})

    def _get_field_names(self):
        """Return list of field names to expose."""
        if self.field_ids:
            return self.field_ids.mapped('name')
        # Default safe fields
        model = self.env[self.model_id.model]
        return list(model._fields.keys())

    def _fetch_data(self, limit=None, offset=0, domain=None, order=None):
        """Fetch records for this endpoint."""
        self.ensure_one()
        model = self.env[self.model_id.model]
        base_domain = eval(self.domain or '[]')  # noqa: S307
        if domain:
            if isinstance(domain, str):
                extra = eval(domain)  # noqa: S307
            else:
                extra = domain
            base_domain = base_domain + extra

        effective_limit = min(limit or self.limit, self.limit)
        effective_order = order or self.order_by or 'id desc'
        field_names = self._get_field_names()

        records = model.search_read(
            domain=base_domain,
            fields=field_names,
            limit=effective_limit,
            offset=offset,
            order=effective_order,
        )
        return records

    def _increment_call_count(self):
        """Update call statistics."""
        self.sudo().write({
            'last_called': fields.Datetime.now(),
            'call_count': self.call_count + 1,
        })
