# -*- coding: utf-8 -*-
# =============================================================================
#  BI Connector — Power BI & Analytics
# -----------------------------------------------------------------------------
#  Location  : King Abdulaziz Branch Road, Riyadh, Saudi Arabia
#  Email     : sales@leapai.ai
#  Phone     : +966 53 553 3627
#  Website   : https://leapai.ai
#  Developer : Abdulkaraim Osman — Tech Manager | Backend Engineer | DevOps Engineer
#              at Bab International Corp For Specialized Services
#  LinkedIn  : https://www.linkedin.com/in/abdulkaraim-o-385b7a110/
# =============================================================================
{
    'name': 'BI Connector — Power BI & Analytics',
    'version': '19.0.1.0.0',
    'category': 'Technical',
    'summary': 'Connect Odoo to Power BI, Tableau & any BI tool via secure OData/REST API with JWT auth',
    'author': 'leapai.ai',
    'maintainer': 'Abdulkaraim Osman',
    'support': 'sales@leapai.ai',
    'website': 'https://leapai.ai',
    'depends': ['base', 'mail', 'web'],
    'data': [
        'security/bi_security.xml',
        'security/ir.model.access.csv',
        'data/bi_data.xml',
        'views/bi_config_views.xml',
        'views/bi_endpoint_views.xml',
        'views/bi_token_views.xml',
        'views/bi_log_views.xml',
        'views/bi_menu.xml',
    ],
    'images': [
        'static/description/banner.png',
        'static/description/screenshots/06_powerbi_dashboard.jpg',
        'static/description/screenshots/03_endpoints.jpg',
        'static/description/screenshots/02_jwt_tokens.jpg',
        'static/description/screenshots/05_access_logs.jpg',
        'static/description/screenshots/01_config_hub.jpg',
        'static/description/screenshots/04_odata_feed.jpg',
    ],
    'application': True,
    'installable': True,
    'license': 'LGPL-3',
}
