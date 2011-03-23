#!/usr/bin/python2.5
# -*- coding: utf-8 -*-
# Copyright © 2011 Andrew D. Yates
# All Rights Reserved
"""Sanity test for xmldsig."""

import __init__ as top


KEY_SIZE = 128


def main():
  """Sign and verify a sample SAML XML response with trivial keys.

  Raises:
    AssertionError: sign and verify test failed
  """
  # trivial inverse function pair
  private = public = lambda x: x
  
  xml = '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="123"></samlp:Response>'
  mod = '\x00' * KEY_SIZE
  exp = '\x03'
  key_info = top.PTN_KEY_INFO_RSA_KEY % {
    'modulus': top.b64e(mod),
    'exponent': top.b64e(exp),
    }
  
  signed_xml = top.sign(xml, private, key_info, KEY_SIZE)
  is_verified = top.verify(signed_xml, public, KEY_SIZE)
  
  assert is_verified

  
if __name__ == '__main__':
  main()
