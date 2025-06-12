"""
https://github.com/cheney-yan/pingdom-py-api-v3
"""
# ===============================================================================
# Copyright (C) 2019-2023 by Cheney Yan
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
# ===============================================================================


__version__ = "0.0.2"
__project_url__ = "https://github.com/cheney-yan/pingdom-py-api-v3"

import sys
import requests

IS_PY3 = sys.version_info[0] == 3

if not IS_PY3:
  raise ValueError("This package only supports python3")


class ApiError(Exception):

  def __init__(self, http_response):
    content = http_response.json()
    self.status_code = http_response.status_code
    self.status_desc = content['error']['statusdesc']
    self.error_message = content['error']['errormessage']
    super(ApiError, self).__init__(self.__str__())

  def __repr__(self):
    return 'pingdomv3.ApiError: HTTP `%s - %s` returned with message, "%s"' % \
           (self.status_code, self.status_desc, self.error_message)

  def __str__(self):
    return self.__repr__()


class Api(object):

  def __init__(self, token):
    self.base_url = "https://api.pingdom.com/api/3.1/"
    self.headers = {'Authorization': 'Bearer %s' % token}

  def send(self, method, resource, resource_id=None, data=None, params=None):
    if data is None:
      data = {}
    if params is None:
      params = {}
    if resource_id is not None:
      resource = "%s/%s" % (resource, resource_id)
    response = requests.request(method, self.base_url + resource,
                                headers=self.headers,
                                data=data,
                                params=params
                                )
    if response.status_code != 200:
      raise ApiError(response)
    else:
      return response.json()


class Client(object):
  """
  Pingdom client
  """

  def __init__(self, token):
    """
    Initializer.

    :param token: Pingdom V3 API Token. Generate from https://my.pingdom.com/3/api-tokens
    """
    self.token = token
    self.api = Api(token)

  def get_checks(self, limit: int = None,
                 offset: int = None,
                 showencryption: bool = None,
                 include_tags: bool = None,
                 include_severity: bool = None,
                 tags: [str] = None
                 ):
    params = {}
    if limit is not None:
      params['limit'] = limit
    if offset is not None:
      params['offset'] = offset
    if showencryption is not None:
      params['showencryption'] = showencryption
    if include_tags is not None:
      params['include_tags'] = include_tags
    if include_severity is not None:
      params['include_severity'] = include_severity
    if tags is not None:
      params['tags'] = ','.join(tags)
    return self.api.send('get', "checks", params=params)['checks']

  def get_check(self, check_id):
    return self.api.send('get', "checks/%s" % check_id)['check']

  def create_check(self, check_detail):
    return self.api.send('POST', "checks", data=check_detail)['check']

  def duplicate_check(self, check_id):
    detail = self.get_check(check_id)
    detail['host'] = str(detail.get('hostname'))
    detail['name'] = 'Copy Of %s' % detail.get('name')
    for unused_key in ('id', 'created', 'hostname', 'lasttesttime', 'lastresponsetime', 'status'):
      detail.pop(unused_key, None)
    if 'tags' in detail:
      detail['tags'] = ','.join([t['name'] for t in detail['tags']])

    return self.create_check(detail)

  def delete_check(self, check_id):
    return self.api.send('delete', 'checks/%s' % check_id)
