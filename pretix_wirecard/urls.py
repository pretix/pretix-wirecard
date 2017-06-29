from django.conf.urls import include, url

from .views import RedirectView, ConfirmView, ReturnView

event_patterns = [
    url(r'^wirecard/', include([
        url(r'^redirect/(?P<order>[^/]+)/(?P<hash>[^/]+)/$', RedirectView.as_view(), name='redirect'),
        url(r'^confirm/(?P<order>[^/]+)/(?P<hash>[^/]+)/$', ConfirmView.as_view(), name='confirm'),
        url(r'^return/(?P<order>[^/]+)/(?P<hash>[^/]+)/$', ReturnView.as_view(), name='return'),
    ])),
]
