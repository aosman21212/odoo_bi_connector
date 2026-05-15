from odoo import models, fields


class BiLog(models.Model):
    _name = 'bi.log'
    _description = 'BI Connector Access Log'
    _rec_name = 'path'
    _order = 'timestamp desc'

    config_id = fields.Many2one(
        'bi.config',
        string='Configuration',
        ondelete='set null',
    )
    token_id = fields.Many2one(
        'bi.token',
        string='Access Token',
        ondelete='set null',
    )
    endpoint_id = fields.Many2one(
        'bi.endpoint',
        string='Endpoint',
        ondelete='set null',
    )
    ip_address = fields.Char(string='IP Address')
    method = fields.Char(string='HTTP Method')
    path = fields.Char(string='Request Path')
    status_code = fields.Integer(string='Status Code')
    response_time = fields.Float(string='Response Time (ms)')
    record_count = fields.Integer(string='Record Count')
    timestamp = fields.Datetime(
        string='Timestamp',
        default=fields.Datetime.now,
    )
    error_message = fields.Text(string='Error Message')
