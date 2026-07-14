CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "py")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "python"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    k.setdefault("type", "bug")
    k.setdefault("qual", "rel")
    k.setdefault("sev", "medium")
    k.setdefault("cwe", "")
    return k


# Python quality pack: removed/deprecated Django and stdlib APIs.
RULES = [
    # --- Django removed APIs ---
    r(id="python-django-render-to-response", title="Django render_to_response", desc="render_to_response was removed in Django 3.0.",
      rationale="render_to_response no longer exists; use render(request, ...).", remediation="Use django.shortcuts.render.",
      source="https://docs.djangoproject.com/en/stable/releases/3.0/", re=r"\brender_to_response\s*\(",
      nc="return render_to_response('page.html', ctx)", c="return render(request, 'page.html', ctx)"),
    r(id="python-django-null-boolean-field", title="Django NullBooleanField", desc="NullBooleanField was removed in Django 4.0.",
      rationale="Use BooleanField(null=True) instead of the removed NullBooleanField.", remediation="Use models.BooleanField(null=True).",
      source="https://docs.djangoproject.com/en/stable/releases/4.0/", re=r"\bNullBooleanField\s*\(",
      nc="active = models.NullBooleanField()", c="active = models.BooleanField(null=True)"),
    r(id="python-django-ipaddress-field", title="Django IPAddressField", desc="IPAddressField was removed in Django 1.9.",
      rationale="Use GenericIPAddressField instead of the removed IPAddressField.", remediation="Use models.GenericIPAddressField.",
      source="https://docs.djangoproject.com/en/stable/releases/1.9/", re=r"\bIPAddressField\s*\(",
      nc="ip = models.IPAddressField()", c="ip = models.GenericIPAddressField()"),
    r(id="python-django-force-text", title="Django force_text", desc="force_text was removed in Django 4.0.",
      rationale="force_text was renamed force_str.", remediation="Use django.utils.encoding.force_str.",
      source="https://docs.djangoproject.com/en/stable/releases/4.0/", re=r"\bforce_text\s*\(",
      nc="value = force_text(obj)", c="value = force_str(obj)"),
    r(id="python-django-smart-text", title="Django smart_text", desc="smart_text was removed in Django 4.0.",
      rationale="smart_text was renamed smart_str.", remediation="Use django.utils.encoding.smart_str.",
      source="https://docs.djangoproject.com/en/stable/releases/4.0/", re=r"\bsmart_text\s*\(",
      nc="value = smart_text(obj)", c="value = smart_str(obj)"),
    r(id="python-django-ugettext", title="Django ugettext", desc="ugettext/ugettext_lazy were removed in Django 4.0.",
      rationale="The u-prefixed translation helpers were removed; gettext is unicode already.", remediation="Use gettext / gettext_lazy.",
      source="https://docs.djangoproject.com/en/stable/releases/4.0/", re=r"\bugettext(_lazy)?\s*\(",
      nc="label = ugettext('Name')", c="label = gettext('Name')"),
    r(id="python-django-is-ajax", title="Django request.is_ajax()", desc="HttpRequest.is_ajax was removed in Django 4.0.",
      rationale="is_ajax relied on a non-standard header and was removed.", remediation="Check the X-Requested-With header explicitly.",
      source="https://docs.djangoproject.com/en/stable/releases/3.1/", re=r"\.is_ajax\s*\(",
      nc="if request.is_ajax():", c='if request.headers.get("x-requested-with") == "XMLHttpRequest":'),
    r(id="python-django-comma-separated-field", title="Django CommaSeparatedIntegerField", desc="CommaSeparatedIntegerField was removed in Django 3.1.",
      rationale="This field type was removed; validate a CharField instead.", remediation="Use a CharField with a validator.",
      source="https://docs.djangoproject.com/en/stable/releases/3.1/", re=r"\bCommaSeparatedIntegerField\s*\(",
      nc="ids = models.CommaSeparatedIntegerField(max_length=50)", c="ids = models.CharField(max_length=50, validators=[v])"),
    # --- stdlib removed / deprecated ---
    r(id="python-base64-encodestring", title="base64.encodestring", desc="base64.encodestring was removed in Python 3.9.",
      rationale="encodestring raises AttributeError on Python 3.9+.", remediation="Use base64.encodebytes.",
      source="https://docs.python.org/3/whatsnew/3.9.html", re=r"\bbase64\.encodestring\s*\(",
      nc="s = base64.encodestring(data)", c="s = base64.encodebytes(data)"),
    r(id="python-base64-decodestring", title="base64.decodestring", desc="base64.decodestring was removed in Python 3.9.",
      rationale="decodestring raises AttributeError on Python 3.9+.", remediation="Use base64.decodebytes.",
      source="https://docs.python.org/3/whatsnew/3.9.html", re=r"\bbase64\.decodestring\s*\(",
      nc="d = base64.decodestring(data)", c="d = base64.decodebytes(data)"),
    r(id="python-cgi-escape", title="cgi.escape()", desc="cgi.escape was removed in Python 3.8.",
      rationale="cgi.escape raises AttributeError on Python 3.8+ and did not escape quotes by default.", remediation="Use html.escape.",
      source="https://docs.python.org/3/whatsnew/3.8.html", re=r"\bcgi\.escape\s*\(",
      nc="safe = cgi.escape(value)", c="safe = html.escape(value)"),
    r(id="python-os-getcwdu", title="Python 2 os.getcwdu()", desc="os.getcwdu was removed in Python 3.",
      rationale="os.getcwdu raises AttributeError on Python 3; getcwd already returns str.", remediation="Use os.getcwd().",
      source="https://docs.python.org/3/whatsnew/3.0.html", re=r"\bos\.getcwdu\s*\(",
      nc="cwd = os.getcwdu()", c="cwd = os.getcwd()"),
    r(id="python-time-clock", title="time.clock()", desc="time.clock was removed in Python 3.8.",
      rationale="time.clock raises AttributeError on Python 3.8+.", remediation="Use time.perf_counter or time.process_time.",
      source="https://docs.python.org/3/whatsnew/3.8.html", re=r"\btime\.clock\s*\(",
      nc="start = time.clock()", c="start = time.perf_counter()"),
    r(id="python-plistlib-readplist", title="plistlib.readPlist()", desc="readPlist/writePlist were removed in Python 3.9.",
      rationale="These camelCase functions raise AttributeError on Python 3.9+.", remediation="Use plistlib.load / plistlib.dump.",
      source="https://docs.python.org/3/whatsnew/3.9.html", re=r"\bplistlib\.(readPlist|writePlist)\s*\(",
      nc="data = plistlib.readPlist(f)", c="data = plistlib.load(f)"),
    r(id="python-etree-getiterator", title="ElementTree getiterator()", desc="getiterator() was removed in Python 3.9.",
      rationale="Element.getiterator raises AttributeError on Python 3.9+.", remediation="Use element.iter().",
      source="https://docs.python.org/3/whatsnew/3.9.html", re=r"\.getiterator\s*\(",
      nc="for node in root.getiterator():", c="for node in root.iter():"),
    r(id="python-pipes-quote", type="smell", qual="maint", sev="low", title="pipes.quote()", desc="pipes.quote is deprecated (pipes was removed in 3.13).",
      rationale="pipes.quote moved to shlex.quote; the pipes module is removed in Python 3.13.", remediation="Use shlex.quote.",
      source="https://docs.python.org/3/whatsnew/3.13.html", re=r"\bpipes\.quote\s*\(",
      nc="arg = pipes.quote(user_input)", c="arg = shlex.quote(user_input)"),
    r(id="python-numpy-matrix", type="smell", qual="maint", sev="low", title="numpy.matrix", desc="np.matrix is deprecated in favor of ndarray.",
      rationale="numpy discourages np.matrix; use a 2-D array.", remediation="Use np.array.",
      source="https://numpy.org/doc/stable/reference/generated/numpy.matrix.html", re=r"\bnp\.matrix\s*\(",
      nc="m = np.matrix(data)", c="m = np.array(data)"),
    r(id="python-numpy-bool8", type="smell", qual="maint", sev="low", title="numpy.bool8 alias", desc="np.bool8 is a deprecated alias.",
      rationale="np.bool8 is deprecated; use np.bool_.", remediation="Use np.bool_.",
      source="https://numpy.org/doc/stable/release/1.24.0-notes.html", re=r"\bnp\.bool8\b",
      nc="dtype = np.bool8", c="dtype = np.bool_"),
    r(id="python-ssl-protocol-sslv23", type="smell", qual="maint", sev="low", title="ssl.PROTOCOL_SSLv23 alias", desc="PROTOCOL_SSLv23 is a deprecated alias for PROTOCOL_TLS.",
      rationale="The SSLv23 name is misleading and deprecated.", remediation="Use PROTOCOL_TLS_CLIENT / PROTOCOL_TLS_SERVER.",
      source="https://docs.python.org/3/library/ssl.html", re=r"\bPROTOCOL_SSLv23\b",
      nc="ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)", c="ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)"),
]
