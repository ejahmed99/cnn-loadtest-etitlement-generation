import urllib.parse
import hashlib
import hmac
import uuid
import time
import base64


class ServerToServerToken:
  def __init__(self, calling_application: str, nonce: str, timestamp: str, algorithm: str, signature: str, body_hash: str=None, issuer: str=None, version: str="2"):
    self.calling_application = calling_application
    self.nonce = nonce
    self.timestamp = timestamp
    self.algorithm = algorithm
    self.signature = signature
    self.body_hash = body_hash
    self.issuer = issuer
    self.version = version

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
    if (self.version is not None):
      parts.append("version=%s" % self.version)

    joiner = ","
    return joiner.join(parts)



class SignatureGenerator:
  __hashing_algs = {}
  __hashing_algs['sha1'] = hashlib.sha1
  __hashing_algs['sha256'] = hashlib.sha256
  __hashing_algs['HmacSHA1'] = hashlib.sha1
  __hashing_algs['HmacSHA256'] = hashlib.sha256


  @staticmethod
  def sign_body_put_data(body: bytes, qParams: dict, calling_application_name: str, uri: str, secret_key: str, encoding_algorithm: str="HmacSHA1") -> ServerToServerToken:

    sig_params = {}
    if (qParams is not None):
      sig_params.update(qParams)
    if (bytes is not None):
      body_hash = SignatureGenerator.encode(body, secret_key, encoding_algorithm)
      sig_params['body_hash'] = body_hash
      sig_params['issuer'] = "cnn:qa:bolt-load-test"
      sig_params['applicationName'] = calling_application_name
      sig_params.update(SignatureGenerator.__get_general_data())

    base_str = SignatureGenerator.build_base_sig_string("PUT", uri, sig_params)


    sig = SignatureGenerator.encode(base_str.encode(), secret_key, encoding_algorithm)

    return ServerToServerToken(calling_application=sig_params['applicationName'], nonce=sig_params['nonce'], timestamp=sig_params['timestamp'], algorithm=encoding_algorithm, signature=sig, body_hash=sig_params['body_hash'], issuer=sig_params['issuer'])

  @staticmethod
  def encode(toencode: bytes, shared_key: str, algorithm: str) -> str:

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

    p_val = SignatureGenerator.__urlencode(key)
    p_val += "="
    p_val += SignatureGenerator.__urlencode(val)
    return p_val

  @staticmethod
  def __urlencode(s: str) -> str:

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

  def __init__(self, algorithm):
    self.algorithm = algorithm