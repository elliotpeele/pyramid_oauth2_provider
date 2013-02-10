#
# Copyright (c) Elliot Peele <elliot@bentlogic.net>
#
# This program is distributed under the terms of the MIT License as found
# in a file called LICENSE. If it is not present, the license
# is always available at http://www.opensource.org/licenses/mit-license.php.
#
# This program is distributed in the hope that it will be useful, but
# without any warrenty; without even the implied warranty of merchantability
# or fitness for a particular purpose. See the MIT License for full details.
#

"""
Custom HTTP exceptions that support rendering to JSON by default.
"""

# NOTE: If you need to add more errors, please subclass errors from
#       httpexceptions as has been done below.

from string import Template

from pyramid import httpexceptions
from pyramid.httpexceptions import text_type
from pyramid.httpexceptions import _no_escape
from pyramid.httpexceptions import WSGIHTTPException

def _quote_escape(value):
    v = _no_escape(value)
    return v.replace('"', '\\"')


class BaseJsonHTTPError(WSGIHTTPException):
    """
    Base error class for rendering errors in JSON.
    """

    json_template_obj = Template('''\
{
    "status": "${status}",
    "code": ${code},
    "explanation": "${explanation}",
    "detail": "${detail}"
}
${html_comment}
''')

    def prepare(self, environ):
        """
        Always return errors in JSON.
        """

        if not self.body and not self.empty_body:
            html_comment = ''
            comment = self.comment or ''
            accept = environ.get('HTTP_ACCEPT', '')
            if 'text/plain' in accept:
                self.content_type = 'text/plain'
                escape = _no_escape
                page_template = self.plain_template_obj
                br = '\n'
                if comment:
                    html_comment = escape(comment)
            else:
                self.content_type = 'aplication/json'
                escape = _quote_escape
                page_template = self.json_template_obj
                br = '\n'
                if comment:
                    html_comment = '# %s' % comment
            args = {
                'br': br,
                'explanation': escape(self.explanation),
                'detail': escape(self.detail or ''),
                'comment': escape(comment),
                'html_comment': html_comment,
                }
            for k, v in environ.items():
                if (not k.startswith('wsgi.')) and ('.' in k):
                    continue
                args[k] = escape(v)
            for k, v in self.headers.items():
                args[k.lower()] = escape(v)
            page = page_template.substitute(status=self.status,
                code=self.code, **args)
            if isinstance(page, text_type):
                page = page.encode(self.charset)
            self.app_iter = [page]
            self.body = page


class HTTPBadRequest(httpexceptions.HTTPBadRequest, BaseJsonHTTPError):
    pass


class HTTPUnauthorized(httpexceptions.HTTPUnauthorized, BaseJsonHTTPError):
    pass


class HTTPMethodNotAllowed(httpexceptions.HTTPMethodNotAllowed,
    BaseJsonHTTPError):
    pass
