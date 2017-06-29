import json

from django.dispatch import receiver
from django.http import HttpRequest, HttpResponse
from django.template.loader import get_template
from django.urls import resolve
from django.utils.translation import ugettext_lazy as _

from pretix.base.middleware import _parse_csp, _merge_csp, _render_csp
from pretix.base.signals import register_payment_providers, logentry_display, requiredaction_display
from pretix.presale.signals import process_response
from .payment import WirecardSettingsHolder, WirecardCC, WirecardBancontact, WirecardEKonto, WirecardEPayBG, \
    WirecardEPS, WirecardGiropay, WirecardIdeal, WirecardMoneta, WirecardPayPal, WirecardPOLi, WirecardPrzelewy24, \
    WirecardPSC, WirecardSEPA, WirecardSkrill, WirecardSOFORT, WirecardTatra, WirecardTrustly, WirecardTrustPay


@receiver(register_payment_providers, dispatch_uid="payment_wirecard")
def register_payment_provider(sender, **kwargs):
    return [WirecardSettingsHolder, WirecardCC, WirecardBancontact, WirecardEKonto, WirecardEPayBG, WirecardEPS,
            WirecardGiropay, WirecardIdeal, WirecardMoneta, WirecardPayPal, WirecardPOLi, WirecardPrzelewy24,
            WirecardPSC, WirecardSEPA, WirecardSkrill, WirecardSOFORT, WirecardTatra, WirecardTrustly, WirecardTrustPay]


@receiver(signal=process_response, dispatch_uid="wirecard_middleware_resp")
def signal_process_response(sender, request: HttpRequest, response: HttpResponse, **kwargs):
    provider = WirecardSettingsHolder(sender)
    url = resolve(request.path_info)
    if provider.settings.get('_enabled', as_type=bool) and ("checkout" in url.url_name or "order.pay" in url.url_name):
        if 'Content-Security-Policy' in response:
            h = _parse_csp(response['Content-Security-Policy'])
        else:
            h = {}

        _merge_csp(h, {
            'form-action': ['checkout.wirecard.com'],
        })

        if h:
            response['Content-Security-Policy'] = _render_csp(h)
    return response


@receiver(signal=logentry_display, dispatch_uid="wirecard_logentry_display")
def pretixcontrol_logentry_display(sender, logentry, **kwargs):
    if logentry.action_type != 'pretix_wirecard.wirecard.event':
        return

    data = json.loads(logentry.data)
    plains = {
        'SUCCESS': _('Charge succeeded.'),
        'PENDING': _('Charge pending.'),
        'CANCEL': _('Charge canceled.'),
        'FAILURE': _('Charge failed.'),
    }

    return _('Wirecard reported an event: {}').format(plains.get(data.get('paymentState'), ''))


@receiver(signal=requiredaction_display, dispatch_uid="wirecard_requiredaction_display")
def pretixcontrol_action_display(sender, action, request, **kwargs):
    if not action.action_type.startswith('pretix_wirecard'):
        return

    data = json.loads(action.data)

    if action.action_type == 'pretix_wirecard.wirecard.overpaid':
        template = get_template('pretix_wirecard/action_overpaid.html')

    ctx = {'data': data, 'event': sender, 'action': action}
    return template.render(ctx, request)
