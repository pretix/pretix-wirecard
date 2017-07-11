import hashlib
import hmac
import json
import logging
from collections import OrderedDict
from urllib.parse import parse_qs

import requests
from django import forms
from django.contrib import messages
from django.template.loader import get_template
from django.utils.crypto import get_random_string
from django.utils.translation import ugettext_lazy as _

from pretix.base.models import Event
from pretix.base.payment import BasePaymentProvider, PaymentException
from pretix.base.services.orders import mark_order_refunded
from pretix.base.settings import SettingsSandbox
from pretix.multidomain.urlreverse import eventreverse, build_absolute_uri

logger = logging.getLogger(__name__)


class WirecardSettingsHolder(BasePaymentProvider):
    identifier = 'wirecard'
    verbose_name = _('Wirecard Checkout Page')
    is_enabled = False

    @property
    def settings_form_fields(self):
        return OrderedDict(
            list(super().settings_form_fields.items()) + [
                ('customer_id',
                 forms.CharField(
                     label=_('Customer ID'),
                 )),
                ('secret',
                 forms.CharField(
                     label=_('Secret'),
                 )),
                ('shop_id',
                 forms.CharField(
                     label=_('Shop ID'),
                     required=False
                 )),
                ('toolkit_password',
                 forms.CharField(
                     label=_('Toolkit password'),
                     help_text=_('Optional. Required to automatically initiate refunds.'),
                     required=False
                 )),
                ('method_cc',
                 forms.BooleanField(
                     label=_('Credit card payments'),
                     required=False,
                 )),
                ('method_bancontact',
                 forms.BooleanField(
                     label=_('Bancontact / Mister Cash (Belgium)'),
                     disabled=self.event.currency != 'EUR',
                     required=False
                 )),
                ('method_ekonto',
                 forms.BooleanField(
                     label=_('eKonto (Czech Republic)'),
                     required=False,
                     disabled=self.event.currency not in ('CZK', 'USD', 'GBP', 'CAD', 'CHF', 'JPY', 'PLN', 'HUF', 'EUR')
                 )),
                ('method_epay_bg',
                 forms.BooleanField(
                     label=_('ePay.bg (Bulgaria)'),
                     required=False,
                     disabled=self.event.currency != 'BGN'
                 )),
                ('method_eps',
                 forms.BooleanField(label=_('eps-Ueberweisung (Austria)'), required=False)),
                ('method_giropay',
                 forms.BooleanField(label=_('Giropay (Germany)'), required=False)),
                ('method_idl',
                 forms.BooleanField(label=_('iDEAL (Belgium, Netherlands)'), required=False)),
                ('method_moneta',
                 forms.BooleanField(
                     label=_('moneta.ru (Russia, Ukraine)'),
                     required=False,
                     disabled=self.event.currency not in ('EUR', 'USD', 'RUB', 'GBP')
                 )),
                ('method_paypal',
                 forms.BooleanField(label=_('PayPal'), required=False)),
                ('method_psc',
                 forms.BooleanField(label=_('paysafecard'), required=False)),
                ('method_przelewy24',
                 forms.BooleanField(
                     label=_('Przelewy24 (Poland)'),
                     required=False,
                     disabled=self.event.currency != 'PLN'
                 )),
                ('method_poli',
                 forms.BooleanField(
                     label=_('POLi (Australia, New Zealand)'),
                     required=False,
                     disabled=self.event.currency not in ('GBP', 'AUD', 'NZD')
                 )),
                ('method_sepadd',
                 forms.BooleanField(label=_('SEPA Direct Debit (Europe)'), required=False)),
                ('method_skrill',
                 forms.BooleanField(label=_('Skrill Digital Wallet'), required=False)),
                ('method_sofort',
                 forms.BooleanField(label=_('SOFORT (Germany, Austria, Switzerland, Belgium, Netherlands, Poland, '
                                            'Italy, Spain)'), required=False)),
                ('method_tatra',
                 forms.BooleanField(label=_('TatraPay (Slovak Republic)'), required=False)),
                ('method_trustly',
                 forms.BooleanField(
                     label=_('Trustly (Poland, Finland, Sweden, Estonia)'),
                     required=False,
                     disabled=self.event.currency not in ('CAD', 'CZK', 'DKK', 'EUR', 'GBP',
                                                          'HUF', 'NOK', 'PLN', 'SEK', 'USD')
                 )),
                ('method_trustpay',
                 forms.BooleanField(label=_('TrustPay (Czech Republic, Hungary, Slovak Republic, Slovenia, Estonia, '
                                            'Latvia, Lithuania, Turkey)'), required=False)),
            ]
        )


class WirecardMethod(BasePaymentProvider):
    method = ''
    wc_payment_type = 'SELECT'
    statement_length = 253
    order_ref_length = 32

    def __init__(self, event: Event):
        super().__init__(event)
        self.settings = SettingsSandbox('payment', 'wirecard', event)

    @property
    def identifier(self):
        return 'wirecard_{}'.format(self.method)

    @property
    def settings_form_fields(self):
        return {}

    @property
    def is_enabled(self) -> bool:
        return self.settings.get('_enabled', as_type=bool) and self.settings.get('method_{}'.format(self.method),
                                                                                 as_type=bool)

    def payment_form_render(self, request) -> str:
        template = get_template('pretix_wirecard/checkout_payment_form.html')
        ctx = {'request': request, 'event': self.event, 'settings': self.settings}
        return template.render(ctx)

    def checkout_confirm_render(self, request) -> str:
        template = get_template('pretix_wirecard/checkout_payment_confirm.html')
        ctx = {'request': request, 'event': self.event, 'settings': self.settings}
        return template.render(ctx)

    def checkout_prepare(self, request, total):
        return True

    def payment_is_valid_session(self, request):
        return True

    def payment_perform(self, request, order) -> str:
        request.session['wirecard_nonce'] = get_random_string(length=12)
        request.session['wirecard_order_secret'] = order.secret
        return eventreverse(self.event, 'plugins:pretix_wirecard:redirect', kwargs={
            'order': order.code,
            'hash': hashlib.sha1(order.secret.lower().encode()).hexdigest(),
        })

    def sign_parameters(self, params: dict, order: list=None) -> dict:
        keys = order or (list(params.keys()) + ['requestFingerprintOrder', 'secret'])
        params['requestFingerprintOrder'] = ','.join(keys)
        payload = ''.join(self.settings.get('secret') if k == 'secret' else params[k] for k in keys)
        params['requestFingerprint'] = hmac.new(
            self.settings.get('secret').encode(), payload.encode(), hashlib.sha512
        ).hexdigest().upper()
        return params

    def params_for_order(self, order, request):
        if not request.session.get('wirecard_nonce'):
            request.session['wirecard_nonce'] = get_random_string(length=12)
            request.session['wirecard_order_secret'] = order.secret
        hash = hashlib.sha1(order.secret.lower().encode()).hexdigest()
        # TODO: imageURL, cssURL?
        return {
            'customerId': self.settings.get('customer_id'),
            'shopId': self.settings.get('shop_id', ''),
            'language': order.locale[:2],
            'paymentType': self.wc_payment_type,
            'amount': str(order.total),
            'currency': self.event.currency,
            'orderDescription': _('Order {event}-{code}').format(event=self.event.slug.upper(), code=order.code),
            'successUrl': build_absolute_uri(self.event, 'plugins:pretix_wirecard:return', kwargs={
                'order': order.code,
                'hash': hash,
            }),
            'cancelUrl': build_absolute_uri(self.event, 'plugins:pretix_wirecard:return', kwargs={
                'order': order.code,
                'hash': hash,
            }),
            'failureUrl': build_absolute_uri(self.event, 'plugins:pretix_wirecard:return', kwargs={
                'order': order.code,
                'hash': hash,
            }),
            'confirmUrl': build_absolute_uri(self.event, 'plugins:pretix_wirecard:confirm', kwargs={
                'order': order.code,
                'hash': hash,
            }).replace(':8000', ''),  # TODO: Remove
            'pendingUrl': build_absolute_uri(self.event, 'plugins:pretix_wirecard:confirm', kwargs={
                'order': order.code,
                'hash': hash,
            }),
            'duplicateRequestCheck': 'yes',
            'serviceUrl': self.event.settings.imprint_url,
            'customerStatement': _('ORDER {order} EVENT {event} BY {organizer}').format(
                event=self.event.slug.upper(), order=order.code, organizer=self.event.organizer.name
            )[:self.statement_length],
            'orderReference': '{code}{id}'.format(
                code=order.code, id=request.session.get('wirecard_nonce')
            )[:self.order_ref_length],
            'displayText': _('Order {} for event {} by {}').format(
                order.code, self.event.name, self.event.organizer.name
            ),
            'pretix_orderCode': order.code,
            'pretix_eventSlug': self.event.slug,
            'pretix_organizerSlug': self.event.organizer.slug,
            'pretix_nonce': request.session.get('wirecard_nonce'),
        }

    def order_pending_render(self, request, order) -> str:
        retry = True
        try:
            if order.payment_info and json.loads(order.payment_info)['paymentState'] == 'PENDING':
                retry = False
        except KeyError:
            pass
        template = get_template('pretix_wirecard/pending.html')
        ctx = {'request': request, 'event': self.event, 'settings': self.settings,
               'retry': retry, 'order': order}
        return template.render(ctx)

    def order_control_render(self, request, order) -> str:
        if order.payment_info:
            payment_info = json.loads(order.payment_info)
        else:
            payment_info = None
        template = get_template('pretix_wirecard/control.html')
        ctx = {'request': request, 'event': self.event, 'settings': self.settings,
               'payment_info': payment_info, 'order': order, 'provname': self.verbose_name}
        return template.render(ctx)

    def order_can_retry(self, order):
        return True

    @property
    def refund_available(self):
        return bool(self.settings.get('toolkit_password'))

    def order_control_refund_render(self, order) -> str:
        if self.refund_available:
            return '<div class="alert alert-info">%s</div>' % _('The money will be automatically refunded.')
        else:
            return super().order_control_refund_render(order)

    def _refund(self, order_number, amount, currency, language):
        params = {
            'customerId': self.settings.get('customer_id'),
            'shopId': self.settings.get('shop_id', ''),
            'toolkitPassword': self.settings.get('toolkit_password'),
            'command': 'refund',
            'language': language,
            'orderNumber': order_number,
            'amount': str(amount),
            'currency': currency
        }
        r = requests.post(
            'https://checkout.wirecard.com/page/toolkit.php',
            data=self.sign_parameters(
                params,
                ['customerId', 'shopId', 'toolkitPassword', 'secret', 'command', 'language', 'orderNumber', 'amount',
                 'currency']
            )
        )
        retvals = parse_qs(r.text)
        if retvals['status'][0] != '0':
            logger.error('Wirecard error during refund: %s' % r.text)
            raise PaymentException(_('Wirecard reported an error: {msg}').format(msg=retvals['message'][0]))

    def order_control_refund_perform(self, request, order) -> "bool|str":
        if order.payment_info:
            payment_info = json.loads(order.payment_info)
        else:
            payment_info = None

        if not payment_info or not self.refund_available:
            mark_order_refunded(order, user=request.user)
            messages.warning(request, _('We were unable to transfer the money back automatically. '
                                        'Please get in touch with the customer and transfer it back manually.'))
            return

        try:
            self._refund(
                payment_info['orderNumber'], order.total, self.event.currency, order.locale[:2]
            )
        except PaymentException as e:
            messages.error(request, str(e))
        except requests.exceptions.RequestException as e:
            logger.exception('Wirecard error: %s' % str(e))
            messages.error(request, _('We had trouble communicating with Wirecard. Please try again and contact '
                                      'support if the problem persists.'))
        else:
            mark_order_refunded(order, user=request.user)


class WirecardCC(WirecardMethod):
    verbose_name = _('Credit card via Wirecard')
    public_name = _('Credit card')
    method = 'cc'
    wc_payment_type = 'CCARD'


class WirecardBancontact(WirecardMethod):
    verbose_name = _('Bancontact via Wirecard')
    public_name = _('Bancontact')
    method = 'bancontact'
    wc_payment_type = 'BANCONTACT_MISTERCASH'
    statement_length = 25
    order_ref_length = 10


class WirecardEKonto(WirecardMethod):
    verbose_name = _('eKonto via Wirecard')
    public_name = _('eKonto')
    method = 'ekonto'
    wc_payment_type = 'EKONTO'
    statement_length = 115
    order_ref_length = 10


class WirecardEPayBG(WirecardMethod):
    verbose_name = _('ePay.bg via Wirecard')
    public_name = _('ePay.bg')
    method = 'epay_bg'
    wc_payment_type = 'EPAY_BG'
    statement_length = 100
    order_ref_length = 64


class WirecardEPS(WirecardMethod):
    verbose_name = _('eps-Ueberweisung via Wirecard')
    public_name = _('eps-Ueberweisung')
    method = 'eps'
    wc_payment_type = 'EPS'
    statement_length = 254
    order_ref_length = 35


class WirecardGiropay(WirecardMethod):
    verbose_name = _('giropay via Wirecard')
    public_name = _('giropay')
    method = 'giropay'
    wc_payment_type = 'GIROPAY'
    statement_length = 254
    order_ref_length = 32


class WirecardIdeal(WirecardMethod):
    verbose_name = _('iDEAL via Wirecard')
    public_name = _('iDEAL')
    method = 'idl'
    wc_payment_type = 'IDL'
    statement_length = 35
    order_ref_length = 32


class WirecardMoneta(WirecardMethod):
    verbose_name = _('moneta.ru via Wirecard')
    public_name = _('moneta.ru')
    method = 'moneta'
    wc_payment_type = 'MONETA'
    statement_length = 25
    order_ref_length = 10


class WirecardPrzelewy24(WirecardMethod):
    verbose_name = _('Przelewy24 via Wirecard')
    public_name = _('Przelewy24')
    method = 'moneta'
    wc_payment_type = 'MONETA'
    statement_length = 25
    order_ref_length = 10


class WirecardPOLi(WirecardMethod):
    verbose_name = _('POLi via Wirecard')
    public_name = _('POLi')
    method = 'poli'
    wc_payment_type = 'POLI'
    statement_length = 9
    order_ref_length = 10


class WirecardSkrill(WirecardMethod):
    verbose_name = _('Skrill Digital Wallet via Wirecard')
    public_name = _('Skrill Digital Wallet')
    method = 'skrill'
    wc_payment_type = 'SKRILLWALLET'
    statement_length = 27
    order_ref_length = 64


class WirecardTatra(WirecardMethod):
    verbose_name = _('TatraPay via Wirecard')
    public_name = _('TatraPay')
    method = 'tatra'
    wc_payment_type = 'TATRAPAY'
    statement_length = 20
    order_ref_length = 64


class WirecardTrustly(WirecardMethod):
    verbose_name = _('Trustly via Wirecard')
    public_name = _('Trustly')
    method = 'trustly'
    wc_payment_type = 'TRUSTLY'
    statement_length = 225
    order_ref_length = 10


class WirecardTrustPay(WirecardMethod):
    verbose_name = _('TrustPay via Wirecard')
    public_name = _('TrustPay')
    method = 'trustpay'
    wc_payment_type = 'TRUSTPAY'


class WirecardPSC(WirecardMethod):
    verbose_name = _('paysafecard via Wirecard')
    public_name = _('paysafecard')
    method = 'psc'
    wc_payment_type = 'PSC'
    statement_length = 254
    order_ref_length = 128


class WirecardPayPal(WirecardMethod):
    verbose_name = _('PayPal via Wirecard')
    public_name = _('PayPal')
    method = 'paypal'
    wc_payment_type = 'PAYPAL'
    statement_length = 254
    order_ref_length = 128

    def params_for_order(self, order, request):
        params = super().params_for_order(order, request)
        cnt = 0
        for i, p in enumerate(order.positions.select_related('item', 'variation')):
            params['basketItem{}ArticleNumber'.format(i + 1)] = str(p.item.pk) + ('-' + str(p.variation.pk) if p.variation else '')
            params['basketItem{}Name'.format(i + 1)] = (str(p.item) + (' - ' + str(p.variation) if p.variation else ''))[:128]
            params['basketItem{}Description'.format(i + 1)] = (str(p.item) + (' - ' + str(p.variation) if p.variation else ''))[:128]
            params['basketItem{}Quantity'.format(i + 1)] = '1'
            params['basketItem{}UnitGrossAmount'.format(i + 1)] = str(p.price)
            params['basketItem{}UnitNetAmount'.format(i + 1)] = str(p.net_price)
            params['basketItem{}UnitTaxRate'.format(i + 1)] = str(p.tax_rate)
            params['basketItem{}UnitTaxAmount'.format(i + 1)] = str(p.tax_value)
            cnt += 1
        params['basketItems'] = str(cnt)
        return params


class WirecardSEPA(WirecardMethod):
    verbose_name = _('SEPA Direct Debit via Wirecard')
    public_name = _('SEPA Direct Debit')
    method = 'sepadd'
    wc_payment_type = 'SEPA-DD'
    statement_length = 254
    order_ref_length = 128


class WirecardSOFORT(WirecardMethod):
    verbose_name = _('SOFORT via Wirecard')
    public_name = _('SOFORT')
    method = 'sofort'
    wc_payment_type = 'SOFORTUEBERWEISUNG'
    statement_length = 27
    order_ref_length = 128
