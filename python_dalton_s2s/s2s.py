import urllib.parse
import hashlib
import hmac
import uuid
import time
import base64


class ServerToServerToken:
  def __init__(self, calling_application: str, nonce: str, timestamp: str, algorithm: str, signature: str, body_hash: str=None, issuer: str=None):
    self.calling_application = calling_application
    self.nonce = nonce
    self.timestamp = timestamp
    self.algorithm = algorithm
    self.signature = signature
    self.body_hash = body_hash
    self.issuer = issuer

  def __str__(self):
    parts = []
    parts.append("nonce=%s" % self.nonce)
    parts.append("timestamp=%s" % self.timestamp)
    parts.append("applicationName=%s" % self.calling_application)
    parts.append("signature=%s" % self.signature)
    parts.append("issuer=%s" % self.issuer)

    if (self.body_hash is not None):
      parts.append("body_hash=%s" % self.body_hash)
    if (self.algorithm is not None):
      parts.append("algorithm=%s" % self.algorithm)

    joiner = ","
    return joiner.join(parts)



class SignatureGenerator:
  __hashing_algs = {}
  __hashing_algs['sha1'] = hashlib.sha1
  __hashing_algs['sha256'] = hashlib.sha256
  __hashing_algs['HmacSHA1'] = hashlib.sha1
  __hashing_algs['HmacSHA256'] = hashlib.sha256

  @staticmethod
  def sign_delete_data(qParams: dict, calling_application_name: str, uri: str, secret_key: str, encoding_algorithm: str="HmacSHA1") -> ServerToServerToken:
    """
    Generates a ServerToServerToken which can be used as authorization for
    a Dalton server-to-server DELETE call.

    Args:
      qParams (dict): a dictionary keyed by strings and containing either a
        string or a list of strings defining the query params that are to be
        passed along with the DELETE call
      calling_application_name (str): the name of the application initiating
        the server-to-server call
      uri (str): the URI where the request will be sent
      secret_key (str): the shared secret between the two applications
      encoding_algorithm (str): the algorithm used to generate the signature

    Returns:
      ServerToServerToken: the information needed to authorize the API call to
        Dalton

    Raises:
      UnknownAlgorithmException: if the specified encoding_algorithm is not
        recognized
    """

    sig_params = {}
    sig_params.update(qParams)
    sig_params.update(SignatureGenerator.__get_general_data())
    sig_params['applicationName'] = calling_application_name

    base_str = SignatureGenerator.build_base_sig_string("DELETE", uri, sig_params)
    sig = SignatureGenerator.encode(base_str.encode(), secret_key, encoding_algorithm)
    return ServerToServerToken(calling_application=sig_params['applicationName'], nonce=sig_params['nonce'], timestamp=sig_params['timestamp'], algorithm=encoding_algorithm, signature=sig)


  @staticmethod
  def sign_get_data(qParams: dict, calling_application_name: str, uri: str, secret_key: str, encoding_algorithm: str="HmacSHA1") -> ServerToServerToken:
    """
    Generates a ServerToServerToken which can be used as authorization for
    a Dalton server-to-server GET call.

    Args:
      qParams (dict): a dictionary keyed by strings and containing either a
        string or a list of strings defining the query params that are to be
        passed along with the GET call
      calling_application_name (str): the name of the application initiating
        the server-to-server call
      uri (str): the URI where the request will be sent
      secret_key (str): the shared secret between the two applications
      encoding_algorithm (str): the algorithm used to generate the signature

    Returns:
      ServerToServerToken: the information needed to authorize the API call to
        Dalton

    Raises:
      UnknownAlgorithmException: if the specified encoding_algorithm is not
        recognized
    """

    sig_params = {}
    sig_params.update(qParams)
    sig_params.update(SignatureGenerator.__get_general_data())
    sig_params['applicationName'] = calling_application_name

    base_str = SignatureGenerator.build_base_sig_string("GET", uri, sig_params)
    sig = SignatureGenerator.encode(base_str.encode(), secret_key, encoding_algorithm)
    return ServerToServerToken(calling_application=sig_params['applicationName'], nonce=sig_params['nonce'], timestamp=sig_params['timestamp'], algorithm=encoding_algorithm, signature=sig)

  @staticmethod
  def sign_form_put_data(bParams: dict, qParams: dict, calling_application_name: str, uri: str, secret_key: str, encoding_algorithm: str="HmacSHA1") -> ServerToServerToken:
    """
    Generates a ServerToServerToken which can be used as authorization for
    a Dalton server-to-server PUT call.  This method should be used when the
    PUT call sends a form body

    Args:
      bParams (dict): a dictionary keyed by strings and containing either a
        string or a list of strings defining the body params that are to be
        passed along with the PUT call
      qParams (dict): a dictionary keyed by strings and containing either a
        string or a list of strings defining the query params that are to be
        passed along with the PUT call
      calling_application_name (str): the name of the application initiating
        the server-to-server call
      uri (str): the URI where the request will be sent
      secret_key (str): the shared secret between the two applications
      encoding_algorithm (str): the algorithm used to generate the signature

    Returns:
      ServerToServerToken: the information needed to authorize the API call to
        Dalton

    Raises:
      UnknownAlgorithmException: if the specified encoding_algorithm is not
        recognized
    """

    sig_params = {}
    if (bParams is not None):
      sig_params.update(bParams)
    if (qParams is not None):
      sig_params.update(qParams)

    sig_params.update(SignatureGenerator.__get_general_data())
    sig_params['applicationName'] = calling_application_name

    base_str = SignatureGenerator.build_base_sig_string("PUT", uri, sig_params)
    sig = SignatureGenerator.encode(base_str.encode(), secret_key, encoding_algorithm)

    return ServerToServerToken(calling_application=sig_params['applicationName'], nonce=sig_params['nonce'], timestamp=sig_params['timestamp'], algorithm=encoding_algorithm, signature=sig)


  @staticmethod
  def sign_body_put_data(body: bytes, qParams: dict, calling_application_name: str, uri: str, secret_key: str, encoding_algorithm: str="HmacSHA1") -> ServerToServerToken:
    """
    Generates a ServerToServerToken which can be used as authorization for
    a Dalton server-to-server PUT call.  This method should be used when the
    PUT call sends a request body that is NOT a form (JSON, XML, etc).

    Args:
      body (bytes): the bytes that make up the body of the PUT call
      qParams (dict): a dictionary keyed by strings and containing either a
        string or a list of strings defining the query params that are to be
        passed along with the PUT call
      calling_application_name (str): the name of the application initiating
        the server-to-server call
      uri (str): the URI where the request will be sent
      secret_key (str): the shared secret between the two applications
      encoding_algorithm (str): the algorithm used to generate the signature

    Returns:
      ServerToServerToken: the information needed to authorize the API call to
        Dalton

    Raises:
      UnknownAlgorithmException: if the specified encoding_algorithm is not
        recognized
    """

    sig_params = {}
    if (qParams is not None):
      sig_params.update(qParams)
    if (bytes is not None):
      body_hash = SignatureGenerator.encode(body, secret_key, encoding_algorithm)
      sig_params['body_hash'] = body_hash
      sig_params['issuer'] = "cnn:qa:bolt-load-test"
      sig_params['applicationName'] = calling_application_name
      sig_params.update(SignatureGenerator.__get_general_data())

    print("the sign params are:", sig_params)
    base_str = SignatureGenerator.build_base_sig_string("PUT", uri, sig_params)

    print("\n=== BASE STRING ===\n", base_str, "\n===================\n")

    sig = SignatureGenerator.encode(base_str.encode(), secret_key, encoding_algorithm)

    return ServerToServerToken(calling_application=sig_params['applicationName'], nonce=sig_params['nonce'], timestamp=sig_params['timestamp'], algorithm=encoding_algorithm, signature=sig, body_hash=sig_params['body_hash'], issuer=sig_params['issuer'])



  @staticmethod
  def sign_form_post_data(bParams: dict, qParams: dict, calling_application_name: str, uri: str, secret_key: str, encoding_algorithm: str="HmacSHA1") -> ServerToServerToken:
    """
    Generates a ServerToServerToken which can be used as authorization for
    a Dalton server-to-server POST call.  This method should be used when the
    POST call sends a form body

    Args:
      bParams (dict): a dictionary keyed by strings and containing either a
        string or a list of strings defining the body params that are to be
        passed along with the POST call
      qParams (dict): a dictionary keyed by strings and containing either a
        string or a list of strings defining the query params that are to be
        passed along with the POST call
      calling_application_name (str): the name of the application initiating
        the server-to-server call
      uri (str): the URI where the request will be sent
      secret_key (str): the shared secret between the two applications
      encoding_algorithm (str): the algorithm used to generate the signature

    Returns:
      ServerToServerToken: the information needed to authorize the API call to
        Dalton

    Raises:
      UnknownAlgorithmException: if the specified encoding_algorithm is not
        recognized
    """

    sig_params = {}
    if (bParams is not None):
      sig_params.update(bParams)
    if (qParams is not None):
      sig_params.update(qParams)

    sig_params.update(SignatureGenerator.__get_general_data())
    sig_params['applicationName'] = calling_application_name

    base_str = SignatureGenerator.build_base_sig_string("POST", uri, sig_params)
    sig = SignatureGenerator.encode(base_str.encode(), secret_key, encoding_algorithm)

    return ServerToServerToken(calling_application=sig_params['applicationName'], nonce=sig_params['nonce'], timestamp=sig_params['timestamp'], algorithm=encoding_algorithm, signature=sig)

  @staticmethod
  def sign_body_post_data(body: bytes, qParams: dict, calling_application_name: str, uri: str, secret_key: str, encoding_algorithm: str="HmacSHA1") -> ServerToServerToken:
    """
    Generates a ServerToServerToken which can be used as authorization for
    a Dalton server-to-server POST call.  This method should be used when the
    POST call sends a request body that is NOT a form (JSON, XML, etc).

    Args:
      body (bytes): the bytes that make up the body of the POST call
      qParams (dict): a dictionary keyed by strings and containing either a
        string or a list of strings defining the query params that are to be
        passed along with the POST call
      calling_application_name (str): the name of the application initiating
        the server-to-server call
      uri (str): the URI where the request will be sent
      secret_key (str): the shared secret between the two applications
      encoding_algorithm (str): the algorithm used to generate the signature

    Returns:
      ServerToServerToken: the information needed to authorize the API call to
        Dalton

    Raises:
      UnknownAlgorithmException: if the specified encoding_algorithm is not
        recognized
    """

    sig_params = {}
    if (qParams is not None):
      sig_params.update(qParams)
    if (bytes is not None):
      body_hash = SignatureGenerator.encode(body, secret_key, encoding_algorithm)
      sig_params['body_hash'] = body_hash

    sig_params.update(SignatureGenerator.__get_general_data())
    sig_params['applicationName'] = calling_application_name

    base_str = SignatureGenerator.build_base_sig_string("POST", uri, sig_params)
    sig = SignatureGenerator.encode(base_str.encode(), secret_key, encoding_algorithm)

    return ServerToServerToken(calling_application=sig_params['applicationName'], nonce=sig_params['nonce'], timestamp=sig_params['timestamp'], algorithm=encoding_algorithm, signature=sig, body_hash=sig_params['body_hash'])

  @staticmethod
  def encode(toencode: bytes, shared_key: str, algorithm: str) -> str:
    """
    Encodes the given bytes (toencode) using the given algorithm and
    secret key.  The encoded bytes are then Base64 encoded and returned.

    Args:
      toencode (bytes): the bytes to hash
      shared_key (str): the secret key to use when encoding
      algorithm (str): the encoding algorithm to use

    Returns:
      str: the hashed and encoded bytes as a Base64 encoded string

    Raises:
      UnknownAlgorithmException: If the specified algorithm is not
        mapped to a known hashing algorithm
    """

    hlib = SignatureGenerator.__hashing_algs.get(algorithm)
    if (hlib is None):
      raise UnknownAlgorithmException(algorithm)

    k = shared_key.encode()

    hashed = hmac.new(k, toencode, hlib)
    hashed_bytes = hashed.digest()
    str_bytes = base64.b64encode(hashed_bytes)
    return str_bytes.decode("utf-8")

  @staticmethod
  def build_base_sig_string(method: str, uri: str, params: dict) -> str:
    sig_pieces = []

    sig_pieces.append(method)
    sig_pieces.append(SignatureGenerator.__urlencode(uri))

    if (params is not None):
      param_pairs = []
      for k in sorted(params.keys()):
        vals = params[k]
        if (isinstance(vals, list)):
          for v in vals.sort():
            p_val = SignatureGenerator.__encode_param(k, v)
            param_pairs.append(p_val)
        else:
          p_val = SignatureGenerator.__encode_param(k, vals)
          param_pairs.append(p_val)

      p_string_joiner = "&"
      p_string = p_string_joiner.join(param_pairs)
      sig_pieces.append(SignatureGenerator.__urlencode(p_string))

    sig_string_joiner = "&"
    base_sig_string = sig_string_joiner.join(sig_pieces)
    return base_sig_string

  @staticmethod
  def __encode_param(key: str, val: str) -> str:
    """
    URL-encodes the given key/value pair in the following format:
    <url-encoded key>=<url-encoded value>

    Args:
      key (str): the key
      val (str): the value

    Returns:
      str: <url-encoded key>=<url-encoded value>
    """

    p_val = SignatureGenerator.__urlencode(key)
    p_val += "="
    p_val += SignatureGenerator.__urlencode(val)
    return p_val

  @staticmethod
  def __urlencode(s: str) -> str:
    """
    URL encodes the given string

    Args:
      s (str): the string to url encode

    Returns:
      str: the url-encoded string
    """

    # Passing an empty string as the "safe" argument.
    # Without that, forward slashes will not be url-encoded.  And since
    # Dalton expects the forward slashes to be url-encoded we have to
    # make sure that they are
    return urllib.parse.quote(s, safe="")

  @staticmethod
  def __get_general_data():
    gen_data = {}

    nonce = str(uuid.uuid1())
    gen_data['nonce'] = nonce

    current_time_millis = int(round(time.time() * 1000))
    gen_data['timestamp'] = str(current_time_millis)

    return gen_data


class UnknownAlgorithmException(Exception):
  """
  Exception indicating that a given hashing algorithm is unknown

  Attributes:
    algorithm -- the algorithm that was provided which is unknown
  """

  def __init__(self, algorithm):
    self.algorithm = algorithm